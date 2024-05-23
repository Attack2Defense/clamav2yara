
# sigtab.py
# This file is automatically generated. Do not edit.
_tabversion = '3.5'

_lr_method = 'LALR'

_lr_signature = 'E0E5B613ABC934DE2700BA181CF62CCE'
    
_lr_action_items = {'LBRACKET':([12,15,21,28,36,37,],[35,-32,-33,35,53,-34,]),'DIGIT':([0,1,2,3,4,5,6,8,9,10,11,12,13,14,15,16,17,18,21,22,23,24,25,26,28,29,32,33,34,35,36,37,38,39,41,43,44,45,46,47,48,49,51,52,53,54,55,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,],[15,15,-22,15,-13,15,-21,-20,15,-18,15,15,-19,15,-32,15,15,-41,-33,15,-36,-38,-43,-40,15,-30,-37,15,15,51,-35,-34,-39,15,-17,-42,51,15,15,-31,-24,15,-7,59,51,59,51,-8,51,59,51,59,59,51,59,-6,-5,15,59,-4,15,15,-15,-14,]),'LBRACE':([1,2,3,4,6,7,8,10,13,15,16,17,18,19,21,23,24,25,26,27,32,36,37,38,40,41,43,47,48,56,57,74,75,],[-12,-22,-23,-13,-21,-1,-20,-18,-19,-32,-9,-16,-41,44,-33,-36,-38,-43,-40,-10,-37,-35,-34,-39,-11,-17,-42,-31,-24,44,44,-15,-14,]),'RPAREN':([2,6,8,10,13,15,18,21,24,25,26,29,30,31,32,33,34,37,38,43,47,48,50,58,],[-22,-21,-20,-18,-19,-32,-41,-33,-38,-43,-40,-30,48,-25,-37,-27,-23,-34,-39,-42,-31,-24,-28,-26,]),'RBRACKET':([51,59,64,70,],[-7,-8,69,73,]),'RBRACE':([51,59,62,63,66,],[-7,-8,67,68,71,]),'MINUS':([44,51,52,54,59,61,],[55,-7,60,62,-8,65,]),'NIBBLEMASK':([0,1,2,3,4,5,6,8,10,11,12,13,14,15,16,17,18,21,23,24,25,26,29,32,33,34,36,37,38,39,42,43,45,46,47,48,49,67,68,71,74,75,],[5,-12,-22,-23,-13,25,-21,-20,-18,5,-37,-19,38,-32,5,5,42,-33,-36,-38,-43,-40,-30,-37,5,-23,-35,-34,-39,38,25,-42,5,5,-31,-24,5,-6,-5,-4,-15,-14,]),'LPAREN':([0,1,2,3,4,6,8,10,11,12,13,15,16,17,18,20,21,23,24,25,26,29,32,33,34,36,37,38,43,45,46,47,48,49,67,68,71,74,75,],[11,-12,-22,-23,-13,-21,-20,-18,11,-37,-19,-32,11,11,-41,11,-33,-36,-38,-43,-40,-30,-37,11,-23,-35,-34,-39,-42,11,11,-31,-24,11,-6,-5,-4,-15,-14,]),'NOT':([0,1,2,3,4,6,8,10,11,12,13,15,16,17,18,21,23,24,25,26,29,32,33,34,36,37,38,43,45,46,47,48,49,67,68,71,74,75,],[20,-12,-22,-23,-13,-21,-20,-18,20,-37,-19,-32,20,20,-41,-33,-36,-38,-43,-40,-30,-37,20,-23,-35,-34,-39,-42,20,20,-31,-24,20,-6,-5,-4,-15,-14,]),'HEXALPHA':([0,1,2,3,4,5,6,8,9,10,11,12,13,14,15,16,17,18,21,22,23,24,25,26,28,29,32,33,34,36,37,38,39,41,43,45,46,47,48,49,67,68,69,71,72,73,74,75,],[21,21,-22,21,-13,21,-21,-20,21,-18,21,21,-19,21,-32,21,21,-41,-33,21,-36,-38,-43,-40,21,-30,-37,21,21,-35,-34,-39,21,-17,-42,21,21,-31,-24,21,-6,-5,21,-4,21,21,-15,-14,]),'ALTERNATIVE':([2,6,8,10,13,15,18,21,24,25,26,29,31,32,33,34,37,38,43,47,48,50,],[-22,-21,-20,-18,-19,-32,-41,-33,-38,-43,-40,-30,49,-37,-27,-23,-34,-39,-42,-31,-24,-28,]),'ANY':([1,2,3,4,6,7,8,10,13,15,16,17,18,19,21,23,24,25,26,27,32,36,37,38,40,41,43,47,48,56,57,74,75,],[-12,-22,-23,-13,-21,-1,-20,-18,-19,-32,-9,-16,-41,46,-33,-36,-38,-43,-40,-10,-37,-35,-34,-39,-11,-17,-42,-31,-24,46,46,-15,-14,]),'$end':([1,2,3,4,6,7,8,10,13,15,16,17,18,19,21,23,24,25,26,27,32,36,37,38,40,41,43,47,48,56,57,74,75,],[-12,-22,-23,-13,-21,-1,-20,-18,-19,-32,-9,-16,-41,0,-33,-36,-38,-43,-40,-10,-37,-35,-34,-39,-11,-17,-42,-31,-24,-2,-3,-15,-14,]),}

_lr_action = {}
for _k, _v in _lr_action_items.items():
   for _x,_y in zip(_v[0],_v[1]):
      if not _x in _lr_action:  _lr_action[_x] = {}
      _lr_action[_x][_k] = _y
del _lr_action_items

_lr_goto_items = {'hexchar':([0,1,3,5,9,11,12,14,16,17,22,28,33,34,39,45,46,49,69,72,73,],[14,22,22,26,22,14,22,37,39,39,37,22,14,22,37,14,14,14,22,22,22,]),'number':([35,44,53,55,60,62,65,],[52,54,61,63,64,66,70,]),'fixedexpr':([0,9,45,46,],[16,27,16,16,]),'fixedstringtwo':([0,9,45,46,],[1,1,1,1,]),'expr':([0,11,16,17,33,45,46,49,],[17,29,17,17,29,17,17,29,]),'signature':([0,45,46,],[19,56,57,]),'lownibble':([0,11,16,17,33,45,46,49,],[6,6,6,6,6,6,6,6,]),'choiceexpr':([11,33,49,],[33,33,33,]),'skipbytes':([0,11,16,17,18,33,45,46,49,],[2,2,2,2,43,2,2,2,2,]),'choiceelems':([11,49,],[30,58,]),'choiceelem':([11,33,49,],[31,50,31,]),'exprwithfixed':([0,45,46,],[7,7,7,]),'repexpr':([0,16,17,45,46,],[9,40,41,9,9,]),'skip':([19,56,57,],[45,45,45,]),'fixedbyte':([0,1,3,9,11,12,16,17,28,33,34,45,46,49,69,72,73,],[12,23,24,28,32,36,32,32,36,32,24,12,12,32,72,74,75,]),'anchoredshortskip':([0,9,45,46,],[4,4,4,4,]),'choice':([0,11,16,17,20,33,45,46,49,],[10,10,10,10,47,10,10,10,10,]),'highnibble':([0,11,16,17,33,45,46,49,],[8,8,8,8,8,8,8,8,]),'fixedstring':([0,11,16,17,33,45,46,49,],[3,34,3,3,34,3,3,34,]),'negatedchoice':([0,11,16,17,33,45,46,49,],[13,13,13,13,13,13,13,13,]),'skipbyte':([0,11,16,17,18,33,45,46,49,],[18,18,18,18,18,18,18,18,18,]),}

_lr_goto = {}
for _k, _v in _lr_goto_items.items():
   for _x, _y in zip(_v[0], _v[1]):
       if not _x in _lr_goto: _lr_goto[_x] = {}
       _lr_goto[_x][_k] = _y
del _lr_goto_items
_lr_productions = [
  ("S' -> signature","S'",1,None,None,None),
  ('signature -> exprwithfixed','signature',1,'p_signature','sig_yacc.py',8),
  ('signature -> signature skip signature','signature',3,'p_signature','sig_yacc.py',9),
  ('signature -> signature ANY signature','signature',3,'p_signature','sig_yacc.py',10),
  ('skip -> LBRACE number MINUS number RBRACE','skip',5,'p_skip','sig_yacc.py',19),
  ('skip -> LBRACE MINUS number RBRACE','skip',4,'p_skip','sig_yacc.py',20),
  ('skip -> LBRACE number MINUS RBRACE','skip',4,'p_skip','sig_yacc.py',21),
  ('number -> DIGIT','number',1,'p_number','sig_yacc.py',30),
  ('number -> number DIGIT','number',2,'p_number','sig_yacc.py',31),
  ('exprwithfixed -> fixedexpr','exprwithfixed',1,'p_exprwithfixed','sig_yacc.py',38),
  ('exprwithfixed -> repexpr fixedexpr','exprwithfixed',2,'p_exprwithfixed','sig_yacc.py',39),
  ('exprwithfixed -> fixedexpr repexpr','exprwithfixed',2,'p_exprwithfixed','sig_yacc.py',40),
  ('fixedexpr -> fixedstringtwo','fixedexpr',1,'p_fixedexpr','sig_yacc.py',48),
  ('fixedexpr -> anchoredshortskip','fixedexpr',1,'p_fixedexpr','sig_yacc.py',49),
  ('anchoredshortskip -> fixedbyte fixedbyte LBRACKET number MINUS number RBRACKET fixedbyte','anchoredshortskip',8,'p_anchoredshortskip','sig_yacc.py',56),
  ('anchoredshortskip -> fixedbyte LBRACKET number MINUS number RBRACKET fixedbyte fixedbyte','anchoredshortskip',8,'p_anchoredshortskip','sig_yacc.py',57),
  ('repexpr -> expr','repexpr',1,'p_repexpr','sig_yacc.py',64),
  ('repexpr -> expr repexpr','repexpr',2,'p_repexpr','sig_yacc.py',65),
  ('expr -> choice','expr',1,'p_expr','sig_yacc.py',72),
  ('expr -> negatedchoice','expr',1,'p_expr','sig_yacc.py',73),
  ('expr -> highnibble','expr',1,'p_expr','sig_yacc.py',74),
  ('expr -> lownibble','expr',1,'p_expr','sig_yacc.py',75),
  ('expr -> skipbytes','expr',1,'p_expr','sig_yacc.py',76),
  ('expr -> fixedstring','expr',1,'p_expr','sig_yacc.py',77),
  ('choice -> LPAREN choiceelems RPAREN','choice',3,'p_choice','sig_yacc.py',81),
  ('choiceelems -> choiceelem','choiceelems',1,'p_choiceelems','sig_yacc.py',85),
  ('choiceelems -> choiceelem ALTERNATIVE choiceelems','choiceelems',3,'p_choiceelems','sig_yacc.py',86),
  ('choiceelem -> choiceexpr','choiceelem',1,'p_choiceelem','sig_yacc.py',93),
  ('choiceelem -> choiceexpr choiceelem','choiceelem',2,'p_choiceelem','sig_yacc.py',94),
  ('choiceexpr -> fixedstring','choiceexpr',1,'p_choiceexpr','sig_yacc.py',101),
  ('choiceexpr -> expr','choiceexpr',1,'p_choiceexpr','sig_yacc.py',102),
  ('negatedchoice -> NOT choice','negatedchoice',2,'p_negatedchoice','sig_yacc.py',109),
  ('hexchar -> DIGIT','hexchar',1,'p_hexchar','sig_yacc.py',113),
  ('hexchar -> HEXALPHA','hexchar',1,'p_hexchar','sig_yacc.py',114),
  ('fixedbyte -> hexchar hexchar','fixedbyte',2,'p_fixedbyte','sig_yacc.py',118),
  ('fixedstringtwo -> fixedbyte fixedbyte','fixedstringtwo',2,'p_fixedstringtwo','sig_yacc.py',122),
  ('fixedstringtwo -> fixedstringtwo fixedbyte','fixedstringtwo',2,'p_fixedstringtwo','sig_yacc.py',123),
  ('fixedstring -> fixedbyte','fixedstring',1,'p_fixedstring','sig_yacc.py',130),
  ('fixedstring -> fixedstring fixedbyte','fixedstring',2,'p_fixedstring','sig_yacc.py',131),
  ('highnibble -> hexchar NIBBLEMASK','highnibble',2,'p_highnibble','sig_yacc.py',138),
  ('lownibble -> NIBBLEMASK hexchar','lownibble',2,'p_lownibble','sig_yacc.py',142),
  ('skipbytes -> skipbyte','skipbytes',1,'p_skipbytes','sig_yacc.py',146),
  ('skipbytes -> skipbyte skipbytes','skipbytes',2,'p_skipbytes','sig_yacc.py',147),
  ('skipbyte -> NIBBLEMASK NIBBLEMASK','skipbyte',2,'p_skipbyte','sig_yacc.py',154),
]
