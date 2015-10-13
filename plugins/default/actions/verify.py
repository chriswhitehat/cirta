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
from lib.util import colors, printStatusMsg, getUserInWithDef, getUserIn, YES

def verifyAttributes(event):
    for attr in [attr for attr in event._fifoAttrs.values() if attr.verify]:
        if attr.conflictsExist():
            printStatusMsg('Warning: %s Conflicts' % attr.name, 30, '-', color=colors.WARNING)
            print('\n'.join(["%s --> %s" %(x, y) for x, y in attr.valuesHistory if y is not None]))
            print('')
        if attr.value:
            event.setAttribute(attr.name, getUserInWithDef(attr.formalName, attr.value), force=True)
        elif attr.alwaysVerify:
            event.setAttribute(attr.name, getUserIn(attr.formalName, allowBlank=True), force=True)
    
    
def checkExceptionalAttrs(event):
    exceptionalAttrs = [attr for attr in event._fifoAttrs.values() if hasattr(attr, 'exceptional') if attr.exceptional]

    if exceptionalAttrs:
        printStatusMsg('Exceptional Attribute', '-', 25)
        
        for attr in exceptionalAttrs:
            print('\n'.join(["%s.%s --> %s" %(x, attr.name, y) for x, y in attr.valuesHistory if y]))
            
        print('')
        while getUserIn('Do you acknowledge?') not in YES:
            True
            
def execute(event):

    checkExceptionalAttrs(event)
    verifyAttributes(event)