import sys, os

hall_folder = sys.argv[1]
output_csv = sys.argv[2]

lines = []

f = open(output_csv, "w")
print("Generation,Fitness,Strategy",file=f)

for file in os.listdir(hall_folder):
    fullpath = os.path.join(hall_folder, file)
    if "hall" in fullpath.split("/")[-1]:
        generation_number = fullpath.split("hall")[1].split(".txt")[0]
        strats = open(fullpath).read().strip().split("\n")[1:]
        for s in strats:
            components = s.split()
            fitness=components[2].replace(":","")
            strategy=f"\"{' '.join(components[3:])}\""
            print(f"{generation_number},{fitness},{strategy}", file=f)

f.close()