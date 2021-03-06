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

import hashlib
# Requires axit api implementation found at https://github.com/chriswhitehat/axit/blob/master/axit.py
# Must also be part of the python environment/path once downloaded and installed on the system
import axit

def playbookInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()

def adhocInput(event):
    inputHeader = '%s Query Options' % FORMAL_NAME
    event.setOutPath()
    event.setDateRange()


def execute(event):

    procFiles = []

    def checkHashes(files):
        hashes = []
        for f in files:
            with open(f, 'rb') as fBinary:
                md5 = hashlib.md5(fBinary.read()).hexdigest()
                if md5 not in hashes:
                    hashes.append(md5)
                    procFiles.append(f)

    if getattr(event, 'extracted_files', None):
        checkHashes(event.extracted_files)

        if procFiles:
            options = axit.processArgs([])
            options.files = procFiles

            ax = axit.FireEyeAX(options)
  
            results = list(ax.poll())

            print('Review submissions: https://%s/malware_analysis/analyses' % AX_HOSTNAME)
