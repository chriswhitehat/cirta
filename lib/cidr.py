'''
Copyright (c) 2014 Chris White

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''
class cidr():
    def __init__(self, mask="192.168.1.1/16", skip255=False, skip0=False):
        self.skip255 = skip255
        self.skip0 = skip0
        
        addr, rng = mask.split("/")
        addr_int = sum((256**(3-i) * int(b)) for i,b in enumerate(addr.split (".")))
        self.start = addr_int & int("0b"+("1"*int(rng)) + "0"*(32-int(rng)),2)
        self.stop = addr_int | int("0b"+("0"*int(rng)) + "1"*(32-int(rng)),2)
        self.current = self.start


    def int2ipstr(self, s):
        s = hex(s)[2:]
        return '.'.join(('%s' % int(x,16) for x in (s[i:2+i] for i in xrange(0,8,2))))

    def ipstr2int(self, addr):
        return

    def __iter__(self):
        return self

    def next(self):
        if self.current > self.stop:
            raise StopIteration
        else:
            self.current += 1
            res = self.int2ipstr(self.current - 1)
            if res.endswith(".0") and self.skip0:
                res = self.next()
            if res.endswith('.255') and self.skip255:
                res = self.next()
            return res