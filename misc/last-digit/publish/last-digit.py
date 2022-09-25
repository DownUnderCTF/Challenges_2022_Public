with open('/flag.txt', 'rb') as f:
    FLAG = int.from_bytes(f.read().strip(), byteorder='big')

assert FLAG < 2**1024

while True:
    print("Enter your number:")
    
    try:
        n = FLAG * int(input("> "))
        print("Your digit is:", str(n)[-1])
    except ValueError:
        print("Not a valid number! >:(")
