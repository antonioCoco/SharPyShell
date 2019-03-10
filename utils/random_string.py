import string
import random


def random_generator():
    chars = string.ascii_lowercase + string.digits
    size = random.randint(5, 15)
    return ''.join(random.choice(chars) for x in range(size))
