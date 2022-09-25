from datetime import datetime as dt
import time

class Adventure():
    def __init__(self, template_div, list_div, input_div):
        self.log_template = template_div.select(".log", from_content=True)
        self.log_list = list_div
        self.new_log_content = input_div

        self.logs = []
    
    def add_log(self, log=None, colour=None):
        log_id = f"log-{len(self.logs)}"

        if log == None:
            # ignore empty log
            if not self.new_log_content.element.value:
                return None

            # create log
            log = {
                "id": log_id,
                "content": self.new_log_content.element.value,
                "created_at": dt.now(),
            }
        else:
            # create log
            log = {
                "id": log_id,
                "content": log,
                "created_at": dt.now(),
            }

        if colour == None:
            colour = "lightgoldenrodyellow"


        self.logs.append(log)

        # add the log element to the page as new node in the list by cloning from a
        # template
        log_html = self.log_template.clone(log_id, to=self.log_list)
        log_html.element.style.background = colour
        log_html_content = log_html.select(".timestamp")
        log_html_content.element.innerText = "[" + log["created_at"].strftime("%Y-%m-%d %I:%M %p") + "]"
        log_html_content.element.style.fontWeight = "bold"
        log_html_content = log_html.select(".text")
        log_html_content.element.innerText = log["content"]
        self.log_list.element.prepend(log_html.element)

        # if log == None:
        self.new_log_content.clear()
    

# -========================================================-
global x 
x = Adventure(
        template_div = Element("log-template"),
        list_div = Element("terminal"),
        input_div = Element("new-log-content")
    )

from js import setTimeout
from pyodide import create_once_callable
import time

timer = 0

def run_line(line, delay, mode=0):
    if mode == 0:
        def script():
            x.add_log(log="(Jimmy)\n" + line, colour="green")
    else:
        def script():
            x.add_log(log="[INSTRUCTIONS]\n" + line, colour="lightgray")
    
    setTimeout(
        create_once_callable(
            script
        ),
        delay * 1000
    )

run_line(
    line="G'day mate! My name is Drop Bear Jimmy. I live in the bush around here! My favourite pass time is eating gum-nuts and scaring tourists in to thinking I exist. Bloody ripper!",
    delay=timer,
    mode=0
)

timer += 3
run_line(
    line="Hey, speaking of actually I've miss placed me favourite stubby. I like to drop it on tourists when they walk under me tree. Doesn't hurt 'em 'cause it's just foam but man does it get 'em running!",
    delay=timer,
    mode=0
)

timer += 3
run_line(
    line="Last I saw it was yesterday arvo when I get to the servo to get a nice can of milk. Are you heading out that way? Do you think you could look for it for me?",
    delay=timer,
    mode=0
)

timer += 1
run_line(
    line="Say:\t(Y)es or (N)o",
    delay=timer,
    mode=1
)

timer += 10
run_line(
    line="Bloody ripper! You're a good lad, you are. I'll just get sleepin' and screamin' here when you get back!",
    delay=timer,
    mode=0
)

timer += 3
run_line(
    line="Thanks a million mate!",
    delay=timer,
    mode=0
)

timer += 3
run_line(
    line="To walk forward type: WALK FORWARD",
    delay=timer,
    mode=1
)

timer += 10
run_line(
    line="Sorry I didn't get that. Try again",
    delay=timer,
    mode=1
)

timer += 5
run_line(
    line="Sorry I didn't get that. Try again",
    delay=timer,
    mode=1
)

timer += 3
run_line(
    line="Sorry I didn't get that. Try again",
    delay=timer,
    mode=1
)

timer += 3
run_line(
    line="Oh I think the game is broken again. Damn, never trust a Python to do a Javascript's job.",
    delay=timer,
    mode=0
)

timer += 3
run_line(
    line="Anyway, you should probably get on with the CTF.",
    delay=timer,
    mode=0
)