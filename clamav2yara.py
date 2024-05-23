import sys
from tqdm import tqdm
from sigalyzer.clamav import parse_signature
from sigalyzer.yara import convert_to_yara

input =  open(sys.argv[1],'r')
output = open(sys.argv[2],'w')
for line in tqdm(input.readlines()):
    try:
        clamav_signature = parse_signature(line.strip())
        yara_rule = convert_to_yara(clamav_signature)
        output.write(yara_rule)
    except Exception as e:
        print(e)
input.close()
output.close()