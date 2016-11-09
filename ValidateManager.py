# -*- coding: UTF-8 -*-
import re
import time

import DeShc
import DecryptManager


class ValidateManager(object):
    def decryptDFP(self, outerDFP):
        if outerDFP != None and len(outerDFP)!=0 :
            if len(outerDFP) != 64:
                print '格式非法'
            deOuterDFP = DeShc.DeShc.deShc(outerDFP)
            if deOuterDFP == None or len(deOuterDFP) != 64 :
                print '格式非法'

            innerDFP_unchecked = deOuterDFP[0, 32]

            possibility_unchecked = deOuterDFP[32, 34]

            expirationTime_unchecked = deOuterDFP[34, 47]
            expirationTime_unchecked_float = float(expirationTime_unchecked)
            now_time = float(time.time())
            signatureDFP_unchecked = deOuterDFP[47, 63]

            oddDFP_unchecked = deOuterDFP[-1]

            oddDFP_checked = DecryptManager.DecryptManager.createParityCode(innerDFP_unchecked + possibility_unchecked +
                                                             expirationTime_unchecked + signatureDFP_unchecked)

            if oddDFP_checked != oddDFP_unchecked:
                print '被修改'

            possibility_unchecked_pattern = re.compile('^[0-9]+$')
            if not possibility_unchecked_pattern.match(possibility_unchecked):
                print '被修改'
            expirationTime_unchecked_pattern = re.compile('^[0-9]+$')
            if not expirationTime_unchecked_pattern.match(expirationTime_unchecked):
                print '被修改'

            if now_time < expirationTime_unchecked_float :
                print '过期'

            signature_checked = DecryptManager.DecryptManager.encryptOrigin(innerDFP_unchecked + possibility_unchecked +
                                                             expirationTime_unchecked, 'bsfit')

            if signature_checked != None and len(signature_checked) != 0:
                if signatureDFP_unchecked != signature_checked:
                    print '被修改'
                return innerDFP_unchecked
            else:
                print '被修改'
        else:
            print '被修改'


