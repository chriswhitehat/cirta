'''
Copyright (c) 2020 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from lib.util import initSSH


def getSguilSql(query, sguilserver=None, serverUser=None, serverPass=None, serverKey=None,
                dbuser='root', dbpass=None, sguildb='securityonion_db', tableSplit=False):
    
    if serverUser:
        if serverKey:
            sguilDBServer = initSSH(sguilserver, u=serverUser, k=serverKey)
        else:
            sguilDBServer = initSSH(sguilserver, user=serverUser, pwd=serverPass, pubpriv=False)
    else:
        sguilDBServer = initSSH(sguilserver)
    
    if not query.endswith(';'):
        query = query + ';'
        
    if dbpass:
        stdin, stdout, stderr = sguilDBServer.exec_command('''mysql -u %s --password=%s -D %s -e "%s"''' % (dbuser, dbpass, sguildb, query))
    else:
        stdin, stdout, stderr = sguilDBServer.exec_command('''mysql -u %s -D %s -e "%s"''' % (dbuser, sguildb, query))
    
    err = stderr.read()
    if err:
        print(err)
        
    if tableSplit:
        return [x.split('\t') for x in stdout.read().splitlines()]
    else:
        return stdout.read()

    
    
def getSguilSensorList(**kwargs):
    return getSguilSql('SELECT hostname FROM sensor WHERE agent_type=\\"pcap\\" AND active=\\"Y\\";', **kwargs).split()[1:]
