import sys  # 옵션 예외처리시 사용(함수 이름 반환)

def AES(InputBytes:str, KeyBytes:str, mode:'E'or'D', Version:'A'or'B'or'C'='A', out:bool=False, save:bool=False): # 16진수인 스트링으로 받아서 state로 변환 후 암호화 진행
    if Version == 'A':
        Bit = 128   # Block 크기
        Nr = 10     # Round 횟수
        Nk = 4      # Word 길이
    else:
        print("%s의 옵션이 틀렸습니다. :%s"%(sys._getframe().f_code.co_name, Version))
        return -1

    if mode == 'E':
        if out == True:
            print('%s %dbit Encrypting Start: Nk = %2d Nr = %2d\n'%(sys._getframe().f_code.co_name, Bit, Nk, Nr))
        I = state(InputBytes)           # State
        K = keys(state(KeyBytes),Nr)    # Key Scheduling
        R = I^K.Stream[0]               # Add Round Key + Cipher key
        
        if out == True:
            I.outPrint()
            K.out()
            R.outPrint()
        

    elif mode == 'D':
        if out == True:
            print('%s %dbit Decrypting Start: Nk = %2d Nr = %2d\n'%(sys._getframe().f_code.co_name, Bit, Nk, Nr))
        

    else:
        print("%s의 옵션이 틀렸습니다. :%s"%(sys._getframe().f_code.co_name, mode))
        return -1

class Table:
    Sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    
    Ibox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

    # 초기값 0x01. 직전값*2 (직전 값이 0x80 이상일 시엔 xor 0x11B연산을 추가.)
    Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36] # 사용하는 워드 / 워드길이 = 필요한 RC수. 128bit에선 44/4 10, 192: 52/6 = 8, 256: 60/8 = 7개 사용.

class state:
    def __init__(self, initValue:str=""):
        S = initValue.split()
        while len(S) < 16:  # 패딩: 남는 부분 0으로 채우기
            S.append('0')

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
        
    def outMain(self):  # 이 파이썬 코드에선 어차피 모든 원소가 한 행렬이 아닌 각각의 변수라서 의미가 없다. 향후 C코드로 넘어가 최적화를 할 때 쓸 아이디어.
        print("\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n\n"%
                         (self.Aa, self.Ba, self.Ca, self.Da,
                          self.Ab, self.Bb, self.Cb, self.Db,
                          self.Ac, self.Bc, self.Cc, self.Dc,
                          self.Ad, self.Bd, self.Cd, self.Dd))    # 계산시
        '''
    def outPrint(self):
        print("%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n%3x%3x%3x%3x\n"%
                          (self.Aa, self.Ab, self.Ac, self.Ad,
                           self.Ba, self.Bb, self.Bc, self.Bd,
                           self.Ca, self.Cb, self.Cc, self.Cd,
                           self.Da, self.Db, self.Dc, self.Dd))   # 출력시
    
    def __xor__(self, otherState):  #otherState 타입 체크 하고싶은데 자기자신이라 정의가 안됨. 어떻게 해결하지?
        newState = state()
        newState.Aa = self.Aa ^ otherState.Aa
        newState.Ba = self.Ba ^ otherState.Ba
        newState.Ca = self.Ca ^ otherState.Ca
        newState.Da = self.Da ^ otherState.Da

        newState.Ab = self.Ab ^ otherState.Ab
        newState.Bb = self.Bb ^ otherState.Bb
        newState.Cb = self.Cb ^ otherState.Cb
        newState.Db = self.Db ^ otherState.Db

        newState.Ac = self.Ac ^ otherState.Ac
        newState.Bc = self.Bc ^ otherState.Bc
        newState.Cc = self.Cc ^ otherState.Cc
        newState.Dc = self.Dc ^ otherState.Dc
        
        newState.Ad = self.Ad ^ otherState.Ad
        newState.Bd = self.Bd ^ otherState.Bd
        newState.Cd = self.Cd ^ otherState.Cd
        newState.Dd = self.Dd ^ otherState.Dd
        
        return newState

class keys:
    def __init__(self, initValue:state, Needs:int):  # 매개변수 기본값과 주석을 동시에 사용할 경우 주석이 먼저.
        self.Stream = []
        self.Stream.append(initValue)
        for j in range(Needs):
            self.Stream.append(state())
        for i in range(Needs):
            self.Stream[i+1].Aa = self.Stream[i].Aa^Table.Sbox[self.Stream[i].Bd]^Table.Rcon[i]
            self.Stream[i+1].Ba = self.Stream[i].Ba^Table.Sbox[self.Stream[i].Cd]
            self.Stream[i+1].Ca = self.Stream[i].Ca^Table.Sbox[self.Stream[i].Dd]
            self.Stream[i+1].Da = self.Stream[i].Da^Table.Sbox[self.Stream[i].Ad]
            
            self.Stream[i+1].Ab = self.Stream[i].Ab^self.Stream[i+1].Aa
            self.Stream[i+1].Bb = self.Stream[i].Bb^self.Stream[i+1].Ba
            self.Stream[i+1].Cb = self.Stream[i].Cb^self.Stream[i+1].Ca
            self.Stream[i+1].Db = self.Stream[i].Db^self.Stream[i+1].Da
            
            self.Stream[i+1].Ac = self.Stream[i].Ac^self.Stream[i+1].Ab
            self.Stream[i+1].Bc = self.Stream[i].Bc^self.Stream[i+1].Bb
            self.Stream[i+1].Cc = self.Stream[i].Cc^self.Stream[i+1].Cb
            self.Stream[i+1].Dc = self.Stream[i].Dc^self.Stream[i+1].Db
        
            self.Stream[i+1].Ad = self.Stream[i].Ad^self.Stream[i+1].Ac
            self.Stream[i+1].Bd = self.Stream[i].Bd^self.Stream[i+1].Bc
            self.Stream[i+1].Cd = self.Stream[i].Cd^self.Stream[i+1].Cc
            self.Stream[i+1].Dd = self.Stream[i].Dd^self.Stream[i+1].Dc
    
    def out(self, num:int=-1):
        if num > len(self.Stream) or num < 0:    # 모두 출력
            for i in range(len(self.Stream)):
                print('%d번째 확장키'%(i))
                self.Stream[i].outPrint()
        else:
            print('%d번째 확장키'%num)
            self.Stream[num].outPrint()

def main():
    AES("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34", "2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c", 'E', save=True, out=True)
    #AES("32 43 f6 a8", "2b 7e 15 16", 'E', True)


if __name__ == "__main__":
    main()


""" 기타 메모

a = "32"
a = int(a,16)
#a = hex(a) # 0x꼴로 출력해주지만 bit수가 달라짐. 28->53으로.(50->0x32). 정확한 작동을 위해 안쓰는걸로 하자. >> 어차피 정확한 bit확인 안되니까 가독성을 위해 사용하자.
print("32", a, 0x32)
print(len("32")*16)
print(sys.getsizeof("32"), sys.getsizeof(a), sys.getsizeof(0x32))

#print("%x"%int("32", 16))


# 패딩 코드
initValue = "aa bb cc dd"
K = initValue.split()
print(K, len(K))
while len(K) < 16:
        K.append('0')
print(K, len(K))


# SBox를 위한 두자리 수 가르기 코드 -> 근데 sbox를 행렬로 구현하면 필요가 없네..    print(Sbox.Sbox[0xcf])
C = state("32 43 f6 a8")
C.outPrint()
print(C.Aa, hex(C.Aa))
print(C.Aa//16, C.Aa%16)

# xor 연산 테스트
C = state("2b 7e 15 16")
C.outPrint()
print(C.Aa, hex(C.Aa))
C.Aa = C.Aa^0x8a
C.outPrint()
print(C.Aa, hex(C.Aa))


# 키 확장 테스트 : 함수의 확장 키 출력 부분 주석 해제하면 각각 출력됨
aa = state("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c")
K = KeyExtended(aa, 'E')


def KeyExtended(Key:state, mode:'E' or 'D'): # 함수보다 클래스가 나을 것 같아 변경. 키 확장 -> 라운드 키 생성
    # state 클래스 정의보다 뒤에 있어야 Key:주석에서 오류가 나지 않음. 번역과정에서 해석돼서 그런듯. AES는 인자값이 아닌 내부코드에서 사용이라 런타임에서 실행돼서 괜찮은걸로 예상됨.
    if mode == 'E':
        Keys = []
        for i in range(11):
            Keys.append(state())
        Keys[0] = Key
        for i in range(10): # 128bit는 10개의 확장키가 필요함. Keys[0]은 초기키. Keys[10]까지 생성.
            Keys[i+1].Aa = Keys[i].Aa^Table.Sbox[Keys[i].Bd]^Table.Rcon[i]
            # 값이 달라서 체크했던 코드. 원인: Bd가 Bb로 잘못 들어가있었음.
            # print(hex(Keys[i].Bd), ':', hex(Table.Sbox[Keys[i].Bd]))
            # print(hex(Keys[i].Aa), hex(Table.Sbox[Keys[i].Bd]), hex(Table.Rcon[i]), ':', hex(Keys[i+1].Aa))
            Keys[i+1].Ba = Keys[i].Ba^Table.Sbox[Keys[i].Cd]
            Keys[i+1].Ca = Keys[i].Ca^Table.Sbox[Keys[i].Dd]
            Keys[i+1].Da = Keys[i].Da^Table.Sbox[Keys[i].Ad]
            
            Keys[i+1].Ab = Keys[i].Ab^Keys[i+1].Aa
            Keys[i+1].Bb = Keys[i].Bb^Keys[i+1].Ba
            Keys[i+1].Cb = Keys[i].Cb^Keys[i+1].Ca
            Keys[i+1].Db = Keys[i].Db^Keys[i+1].Da
            
            Keys[i+1].Ac = Keys[i].Ac^Keys[i+1].Ab
            Keys[i+1].Bc = Keys[i].Bc^Keys[i+1].Bb
            Keys[i+1].Cc = Keys[i].Cc^Keys[i+1].Cb
            Keys[i+1].Dc = Keys[i].Dc^Keys[i+1].Db
        
            Keys[i+1].Ad = Keys[i].Ad^Keys[i+1].Ac
            Keys[i+1].Bd = Keys[i].Bd^Keys[i+1].Bc
            Keys[i+1].Cd = Keys[i].Cd^Keys[i+1].Cc
            Keys[i+1].Dd = Keys[i].Dd^Keys[i+1].Dc

            # c확장키 출력
            # print('%d번째 확장키'%(i+1))
            # Keys[i+1].outPrint()
        return Keys

    elif mode == 'D':
        pass

    else:
        print("%s의 옵션이 틀렸습니다. :%s"%(sys._getframe().f_code.co_name, mode))
        return -1



# 클래스 키 확장 테스트
aa = state("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c")
K = keys(aa)
# print(K.out())
K.out()

"""