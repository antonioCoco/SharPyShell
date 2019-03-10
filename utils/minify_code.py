def minify_code(ps_code):
    ps_code = ps_code.replace('\t', '')
    ps_code = ps_code.replace('\r\n', '')
    ps_code = ps_code.replace('\n', '')
    ps_code = ps_code.replace('  ', '')
    return ps_code
