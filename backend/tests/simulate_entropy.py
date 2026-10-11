import os

folder = "C:/watchdog/test_folder"

# Write a normal file first
with open(f"{folder}/normal.txt", "w") as f:
    f.write("this is a normal document with regular text content " * 50)

# Now overwrite it with random bytes (simulating encryption)
with open(f"{folder}/normal.txt", "wb") as f:
    f.write(os.urandom(4096))

print("Done — check your dashboard")