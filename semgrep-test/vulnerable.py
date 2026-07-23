import os
import subprocess


password = "admin123"


def run_command(user_input):

    os.system(user_input)



def execute():

    subprocess.call(
        "ls " + input()
    )


execute()