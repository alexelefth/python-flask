def mongo_nosqli_prevent(string):
    escaped = string.replace("$", '').replace("'", '').replace("\"", '')
    return escaped

string = "ghasdgasdg$\'\'gasd\"gasdg"
print(string)
escaped = mongo_nosqli_prevent(string)
print(escaped)
