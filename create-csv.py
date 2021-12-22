import csv
import re
import sys

import boto3


def getparameters(root='/RootLogin'):
    ssm = boto3.client('ssm')
    kwargs = {
        'Path': root,
        'Recursive': True,
        'WithDecryption': True,
    }
    params = []
    while True:
        ret = ssm.get_parameters_by_path(**kwargs)
        if 'Parameters' in ret:
            params.extend(ret['Parameters'])
        if 'NextToken' in ret:
            kwargs['NextToken'] = ret['NextToken']
        else:
            break
    return params


def translate(params, regexes):
    tparams = []
    email = password = accountNo = mfaseed = ""
    for p in params:
        name = p['Name'].strip().replace("/RootLogin/", "")
        val = p['Value'].strip()
        fields = extractfields(regexes, name, val)
        xlist = ["acctnum", "email", "password","mfa"]
        for key in xlist:
            if key not in fields:
                fields[key] = ""
                print(f"acct: {name}: field {key} missing")
        line = ["", "", name, "", "", 0, fields["acctnum"], fields["email"], fields["password"], fields["mfa"]]
        tparams.append(line)
    return tparams

def extractfields(regexes,aname,sval):
    op = {}
    for key in regexes:
        #print(f"{aname}: {key}")
        tmp = sval.split("\n")
        for xi in range(0, len(tmp)):
            m = regexes[key].match(tmp[xi])
            if m is not None:
                xdict = m.groupdict()
                for xkey in xdict:
                    op[xkey] = xdict[xkey].strip()
        clean = sval
        for key in op:
            clean = clean.replace(op[key], "")
        op["password"] = clean.strip()
    return op

acctnum = r".*^(?P<acctnum>[0-9]{12})$.*"
email = r".*^(?P<email>.*@(centrica|britishgas|hivehome|bgch)\..*)$.*"
mfa = r".*^(?P<mfa>[A-Z0-9]{64})$.*"

regexes = {}
regexes["email"] = re.compile(email)
regexes["mfa"] = re.compile(mfa)
regexes["acctnum"] = re.compile(acctnum)

params = getparameters()
lines = translate(params, regexes)

with open('parameters.csv', 'w') as csvfile:
    thewriter = csv.writer(csvfile)

    thewriter.writerow(['collections', 'type', 'name', 'notes', 'fields',
                       'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'])
    for line in lines:
        thewriter.writerow(line)


# collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
