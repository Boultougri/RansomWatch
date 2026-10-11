import os
import time

folder = "C:/watchdog/test_folder"

# Rapidly create files
for i in range(15):
    path = os.path.join(folder, f"file_{i}.txt")
    with open(path, "w") as f:
        f.write("test content")
    time.sleep(0.1)

# Rename some to .locked
for i in range(5):
    src = os.path.join(folder, f"file_{i}.txt")
    dst = os.path.join(folder, f"file_{i}.locked")
    try:
        os.rename(src, dst)
    except:
        pass
    time.sleep(0.1)

print("Done!")