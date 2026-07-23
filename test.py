user_input = input()

# SQL Injection
query = "SELECT * FROM users WHERE id = " + user_input

# Hardcoded Secret
API_KEY = "123456"

# Command Injection
import os
os.system("ls " + user_input)