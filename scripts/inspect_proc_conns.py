import psutil

p = psutil.Process(18016)
for c in p.connections():
    print(c)

