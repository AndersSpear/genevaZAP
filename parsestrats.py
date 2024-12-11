import sys

print(sys.argv[2:])

def proccess(x): # Parse the strategy
    return [float(x.split(",")[1]),",".join(x.strip().split(",")[2:])]

files = []
for arg in sys.argv[2:]:
    f = list(map(lambda x: proccess(x),open(arg).read().strip().split("\n")[1:]))
    files.append(f)

print(len(files))

keywords = {"options":[],"flags":[]}

# methods = ['flags','seq','ack','options-eol', 'options-uto', 'options-sack', 'options-nop', 'options-altchksum', 'options-wscale', 'options-timestamp', 'options-sackok', 'options-mss', 'options-md5header', 'options-altchksumopt']

strats = {"fragment{ip":0,"fragment{tcp":0,"duplicate(":0,"drop":0}
strats = {"fragment{ip":[0] * len(files),"fragment{tcp":[0] * len(files)}

# Construct the tamper stragies
for f in files:
    for ele in f:
        tampers = ele[1].split("tamper{")
        for t in tampers[1:]:
            body = ":".join(t.split(":")[:3])
            body = body.split("}")[0]
            if "tamper{"+body not in strats.keys():
                strats["tamper{"+body] = [0] * len(files)

# for m in methods:
#     strats["tamper{TCP:"+m] = 0

for i, f in enumerate(files):
    for ele in f:
        if ele[0] == -360:
        # if True:
            for k in strats.keys():
                if k in ele[1]:
                    strats[k][i] = strats[k][i] + 1
            # print(ele[1])

# strats = dict(sorted(strats.items(), key=lambda item: item[1], reverse=True))
f = open(sys.argv[1],"w")
print(f"tamper,{','.join(sys.argv[2:])}",file=f)
for k in strats.keys():
    for e in strats[k]:
        if e > 2000:
            print(f'{k.replace("tamper{TCP:","")},{",".join(list(map(str,strats[k])))}',file=f)
            break

f.close()