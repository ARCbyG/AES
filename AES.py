def AES(InputBytes, KeyBytes, mode:'E' or 'D'): # 16진수인 스트링으로 받아서 state로 변환 후 암호화 진행
    if mode == 'E':
        I = state(InputBytes)
        K = state(KeyBytes)
        I.outMain()
        I.outPrint()
        K.outMain()
        K.outPrint()

    elif mode == 'D':
        pass

    else:
        print("AES 모드가 설정되지 않았습니다.")
        return -1

class state:
    
    def __init__(self, initValue):
        S = initValue.split()

        self.Aa = int(S[0], 16)
        self.Ba = int(S[1], 16)
        self.Ca = int(S[2], 16)
        self.Da = int(S[3], 16)
        
        self.Ab = int(S[4], 16)
        self.Bb = int(S[5], 16)
        self.Cb = int(S[6], 16)
        self.Db = int(S[7], 16)
        
        self.Ac = int(S[8], 16)
        self.Bc = int(S[9], 16)
        self.Cc = int(S[10], 16)
        self.Dc = int(S[11], 16)
        
        self.Ad = int(S[12], 16)
        self.Bd = int(S[13], 16)
        self.Cd = int(S[14], 16)
        self.Dd = int(S[15], 16)

        '''
        print("\n%2x %2x %2x %2x \n%2x %2x %2x %2x \n%2x %2x %2x %2x \n%2x %2x %2x %2x \n\n"%
                         (self.Aa, self.Ba, self.Ca, self.Da,
                          self.Ab, self.Bb, self.Cb, self.Db,
                          self.Ac, self.Bc, self.Cc, self.Dc,
                          self.Ad, self.Bd, self.Cd, self.Dd))   # StateMain 출력 예시 = outMain함수와 같음.

        self.StateMain = [self.Aa, self.Ba, self.Ca, self.Da,
                          self.Ab, self.Bb, self.Cb, self.Db,
                          self.Ac, self.Bc, self.Cc, self.Dc,
                          self.Ad, self.Bd, self.Cd, self.Dd]    # 계산시

        self.StatePrint = [self.Aa, self.Ab, self.Ac, self.Ad,
                           self.Ba, self.Bb, self.Bc, self.Bd,
                           self.Ca, self.Cb, self.Cc, self.Cd,
                           self.Da, self.Db, self.Dc, self.Dd]   # 출력시
        '''
    def outMain(self):
        print("\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n\n"%
                         (self.Aa, self.Ba, self.Ca, self.Da,
                          self.Ab, self.Bb, self.Cb, self.Db,
                          self.Ac, self.Bc, self.Cc, self.Dc,
                          self.Ad, self.Bd, self.Cd, self.Dd))    # 계산시
    def outPrint(self):
        print("\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n\n"%
                          (self.Aa, self.Ab, self.Ac, self.Ad,
                           self.Ba, self.Bb, self.Bc, self.Bd,
                           self.Ca, self.Cb, self.Cc, self.Cd,
                           self.Da, self.Db, self.Dc, self.Dd))   # 출력시

        


def main():
    AES("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34", "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c", 'E')
    #print("%x"%int("32", 16))
    

if __name__ == "__main__":
    main()


""" 기타 메모

a = "32"
a = int(a,16)
#a = hex(a) # 0x꼴로 출력해주지만 bit수가 달라짐. 28->53으로.(50->0x32). 정확한 작동을 위해 안쓰는걸로 하자. >> 어차피 정확한 bit확인 안되니까 가독성을 위해 사용하자.
print("32", a, 0x32)
print(len("32")*16)
print(sys.getsizeof("32"), sys.getsizeof(a), sys.getsizeof(0x32))

"""