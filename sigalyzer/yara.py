from __future__ import absolute_import

import re

from .common import PCRE, SignatureParseException, \
   FixedByte, FixedString, FixedStringLenTwo, Skip, \
   Choice, ShortSkip, Not, HighNibble, LowNibble 
from .common import CondSubsignature, \
    CondAnd, CondOr, CondMatchExact, CondMatchMore, \
    CondMatchLess
from .clamav import NdbSignature, LdbSignature, parse_signature
from .clamav import AbsoluteOffset, EPRelativeOffset, \
    InSectionOffset, SectionRelativeOffset, EOFRelativeOffset, \
    AnyOffset


def _to_yara_pattern(sig,modifiers=''):
    if isinstance(sig, PCRE):
        return sig.str
    if isinstance(sig, FixedByte):
        if 'i' in modifiers and 'w' in modifiers:
            if int(sig.value,16) >= ord('a') and int(sig.value,16) <= ord('z'):
                return '(%02X|%02X) 00'%(int(sig.value,16)-32,int(sig.value,16))
            if int(sig.value,16) >= ord('A') and int(sig.value,16) <= ord('Z'):
                return '(%02X|%02X) 00'%(int(sig.value,16),int(sig.value,16)+32)
        elif 'i' in modifiers:
            if int(sig.value,16) >= ord('a') and int(sig.value,16) <= ord('z'):
                return '(%02X|%02X)'%(int(sig.value,16)-32,int(sig.value,16))
            if int(sig.value,16) >= ord('A') and int(sig.value,16) <= ord('Z'):
                return '(%02X|%02X)'%(int(sig.value,16),int(sig.value,16)+32)
        elif 'w' in modifiers:
            return sig.value+' 00'
        return sig.value
    if isinstance(sig, FixedString):
        return " ".join(_to_yara_pattern(x,modifiers) for x in sig.fixed_bytes)
    elif isinstance(sig, Skip):
        min = "{:d}".format(sig.min)
        max = "" if sig.max == Skip.INFINITY else "%d" % sig.max
        return "[%s-%s]" % (min, max)
    elif isinstance(sig, ShortSkip):
        return "[%d-%d]" % (sig.min, sig.max)
    elif isinstance(sig, HighNibble):
        return "%s?" % sig.nibble
    elif isinstance(sig, LowNibble):
        return "?%s" % sig.nibble
    elif isinstance(sig, Not):
        return "??"
        #raise NotImplementedError("Negation is not yet implemented for yara signature conversion")
    elif isinstance(sig, Choice):
        return "(%s)" % "|".join(_to_yara_pattern(x,modifiers) for x in sig.choice)
    elif isinstance(sig, list):
        return " ".join(_to_yara_pattern(x,modifiers) for x in sig)

def _get_subsignatures(cond):
    if isinstance(cond, CondSubsignature):
        return ["subsig_%02d" % cond.number]
    elif isinstance(cond, CondAnd):
        return _get_subsignatures(cond.a) + _get_subsignatures(cond.b)
    elif isinstance(cond, CondOr):
        return _get_subsignatures(cond.a) + _get_subsignatures(cond.b)
    elif isinstance(cond, CondMatchExact):
        return _get_subsignatures(cond.condition)
    elif isinstance(cond, CondMatchLess):
        return _get_subsignatures(cond.condition)
    elif isinstance(cond, CondMatchMore):
        return _get_subsignatures(cond.condition)
    

def _to_yara_condition(cond,offset_conditions={}):
    if isinstance(cond, CondSubsignature):
        if int(cond.number) in offset_conditions and offset_conditions[int(cond.number)] != "true":    
            return offset_conditions[int(cond.number)]
        return "$subsig_%02d" % cond.number
    elif isinstance(cond, CondAnd):
        return "(%s) and (%s)" % (_to_yara_condition(cond.a,offset_conditions), _to_yara_condition(cond.b,offset_conditions))
    elif isinstance(cond, CondOr):
        return "(%s) or (%s)" % (_to_yara_condition(cond.a,offset_conditions), _to_yara_condition(cond.b,offset_conditions))
    elif isinstance(cond, CondMatchExact):
        if cond.count == 0:
            if cond.min_signatures != 0:
                raise NotImplementedError("Support for minimum number of different matching signatures is not implemented!")

            return "not (%s)" % _to_yara_condition(cond.condition,offset_conditions)

        min_signatures = ""
        if cond.min_signatures != 0:
            min_signatures = " and %d of (%s)" % (cond.min_signatures, ",".join("$%s" % x for x in _get_subsignatures(cond.condition,offset_conditions)))

        subpattern_count = " + ".join("#%s" % x for x in _get_subsignatures(cond.condition,offset_conditions))

        return "(%s) and (%s) == %d%s" % (_to_yara_condition(cond.condition,offset_conditions), subpattern_count, cond.count, min_signatures)
    elif isinstance(cond, CondMatchLess):
        min_signatures = ""
        if cond.min_signatures != 0:
            min_signatures = " and %d of (%s)" % (cond.min_signatures, ",".join("$%s" % x for x in _get_subsignatures(cond.condition,offset_conditions)))

        subpattern_count = " + ".join("#%s" % x for x in _get_subsignatures(cond.condition,offset_conditions))

        return "(%s) and (%s) < %d%s" % (_to_yara_condition(cond.condition,offset_conditions), subpattern_count, cond.count, min_signatures)
    elif isinstance(cond, CondMatchMore):
        min_signatures = ""
        if cond.min_signatures != 0:
            min_signatures = " and %d of (%s)" % (cond.min_signatures, ",".join("$%s" % x for x in _get_subsignatures(cond.condition,offset_conditions)))

        subpattern_count = " + ".join("#%s" % x for x in _get_subsignatures(cond.condition,offset_conditions))

        return "(%s) and (%s) > %d%s" % (_to_yara_condition(cond.condition,offset_conditions), subpattern_count, cond.count, min_signatures)

def _target_type_condition(target_type):
    if target_type == 0:
        return "true"
    elif target_type == 1:
        return "uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550"
    elif target_type == 6:
        return "uint32(0) == 0x464C457F"
    else:
        return "true"
        raise NotImplementedError("Target type %d is not yet implemented" % target_type)

def _offset_condition(offset, rulename):
    if isinstance(offset, AnyOffset):
        return "true"
    elif isinstance(offset, AbsoluteOffset):
        if offset.end is None:
            return "$%s at %d" % (rulename, offset.start)
        else:
            return "$%s in (%d..%d+%d)" % (rulename, offset.start, offset.start, offset.end)
    elif isinstance(offset, EPRelativeOffset):
        offs = abs(offset.offset)
        sign = "+" if offset.offset >= 0 else "-"
        if offset.shift is None:
            return "$%s at (pe.entry_point %s %d)" % ( rulename, sign, offs)
        else:
            return "$%s in (pe.entry_point%s%d..pe.entry_point%s%d+%d)" % \
                (rulename, sign, offs, sign, offs, offset.shift)
    elif isinstance(offset, EOFRelativeOffset):
        if offset.shift is None:
            return "$%s at (filesize-%d)" % (rulename, offset.offset)
        else:
            return "$%s in (filesize-%d..filesize-%d+%d)" % (rulename, offset.offset, offset.offset, offset.shift)
    elif isinstance(offset, InSectionOffset):
        return "$%s in (pe.sections[%d].raw_data_offset..pe.sections[%d].raw_data_offset+pe.sections[%d].raw_data_size)" % \
            (offset.section, offset.section, offset.section)
    elif isinstance(offset, SectionRelativeOffset):
        if offset.shift is None:
            return "$%s at (pe.sections[%d].raw_data_offset+%d)" % (offset.section, offset.offset)
        else:
            return "$%s in (pe.sections[%d].raw_data_offset+%d..pe.sections[%d].raw_data_offset+%d+%d)" % \
                (offset.section, offset.offset, offset.section, offset.offset, offset.shift)
    else:
        raise NotImplementedError("Offset type %s is not implemented" % offset.__class__.__name__)

def convert_to_yara(signature, offset_converter = _offset_condition):
    name = re.sub(r'[^0-9A-Za-z_]', '_', signature.name)
    if name[0] in '0123456789':
        name = "_" + name
    target_type_condition = _target_type_condition(signature.target_type)
    if isinstance(signature, NdbSignature):
        '''
        offset_condition = offset_converter(signature.signature.offset, "pattern")
        return """rule %s {
    strings:
        $pattern = { %s }
    condition:
        (%s) and (%s) and $pattern
}\n""" % (name, _to_yara_pattern(signature.signature.signature, signature.signature.modifiers), target_type_condition, offset_condition)
        '''
        offset_condition = offset_converter(signature.signature.offset, "pattern")
        rule_tempate ='''rule {} {{
    strings:
        $pattern = {{ {} }}
    condition:
        {}
}}\n'''
        strings = _to_yara_pattern(signature.signature.signature, signature.signature.modifiers)
        conditions = ""
        if target_type_condition != "true":
            conditions += "({}) and ".format(target_type_condition)
        if offset_condition != "true":
            conditions += "({})".format(offset_condition)
        else:
            conditions += "({})".format("$pattern")

        return rule_tempate.format( name,strings,conditions )
    
    elif isinstance(signature, LdbSignature):
        offset_conditions = {}
        patterns = []
        for i, subsig in enumerate(signature.subsignatures):
            subsig_name = "subsig_%02d" % i
            offset_conditions[i] = offset_converter(subsig.offset, subsig_name)
            if isinstance(subsig.signature, PCRE):
                patterns.append((subsig_name, _to_yara_pattern(subsig.signature, subsig.modifiers)))
            else:
                patterns.append((subsig_name, '{ '+_to_yara_pattern(subsig.signature, subsig.modifiers)+' }'))

        '''
        return """rule %s {
    strings:
        %s
    condition:
        (%s) and (%s) and (%s)
}\n""" % (name, "\n        ".join("$%s = %s" % ptrn for ptrn in patterns), target_type_condition, " and ".join("(%s)" % x for x in offset_conditions), _to_yara_condition(signature.condition))
        '''

        # fix the bug for rule generate 

        rule_tempate = '''rule {} {{
    strings:
        {}
    condition:
        {}
}}\n'''
        strings = "\n        ".join("$%s = %s" % ptrn for ptrn in patterns)
        # target_type_condition_ = target_type_condition
        # offset_conditions_ = " and ".join("(%s)" % x for x in offset_conditions)
        conditions = ""
        if target_type_condition != "true":
            conditions += "({}) and ".format(target_type_condition)
        rule_conditions_ = _to_yara_condition(signature.condition,offset_conditions)
        if rule_conditions_ !="":
            conditions += "({})".format(rule_conditions_)
        return rule_tempate.format( name,strings,conditions)
    