def normalize_args(args):
    normalized_args = []
    if type(args) == str:
        args = [args]
    for i in range(0, len(args)):
        arg = ''.join(args[i])
        if arg.startswith("'") and arg.endswith("'"):
            normalized_args.append(arg[1:-1])
        else:
            normalized_args.append(arg)
    return normalized_args
