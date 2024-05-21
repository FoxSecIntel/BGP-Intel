import random
import sys
import re

def generate_random_ip():
    while True:
        ip = f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        if not re.match(r"^(10|172|192)\.", ip):
            return ip

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py number_of_ips")
        sys.exit(1)

    try:
        num_ips = int(sys.argv[1])
    except ValueError:
        print("The number_of_ips should be an integer.")
        sys.exit(1)

    for _ in range(num_ips):
        ip = generate_random_ip()
        print(ip)

if __name__ == "__main__":
    main()
