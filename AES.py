import sys  # 옵션 예외처리시 사용(함수 이름 반환)
def stetesOut(Names:list, *states):
    Nk = len(states[0].STATE[0])
    A, B, C, D = [], [], [], []
    for i in range(len(states)):
        for j in range(Nk):
            if j == 0:
                A.append([])
                B.append([])
                C.append([])
                D.append([])
            A[i].append(states[i].STATE[0][j])
            B[i].append(states[i].STATE[1][j])
            C[i].append(states[i].STATE[2][j])
            D[i].append(states[i].STATE[3][j])

    for i in range(0,len(Names)):
        if Nk == 4:
            print("   | %11s |"%Names[i], end='') if Names[i] != 'Empty' else print("%18s"%'', end='')
        elif Nk == 6:
            print("   | %17s |"%Names[i], end='') if Names[i] != 'Empty' else print("%24s"%'', end='')
        elif Nk == 8:
            print("   | %23s |"%Names[i], end='') if Names[i] != 'Empty' else print("%30s"%'', end='')
        else:
            print("정체를 알 수 없는 state")
    print()
    for i in range(0,len(A)):
        if Names[i] == 'Empty':
            print("%18s"%'', end='')
        else:
            print("   | ", end='')
            for j in range(0, Nk):
                print("%02x "%A[i][j], end='')
            print("|", end='')
    print()
    for i in range(0,len(B)):
        if Names[i] == 'Empty':
            print("%18s"%'', end='')
        else:
            print("   | ", end='')
            for j in range(0, Nk):
                print("%02x "%B[i][j], end='')
            print("|", end='')
    print()
    for i in range(0,len(C)):
        if Names[i] == 'Empty':
            print("%18s"%'', end='')
        else:
            print("   | ", end='')
            for j in range(0, Nk):
                print("%02x "%C[i][j], end='')
            print("|", end='')
    print()
    for i in range(0,len(D)):
        if Names[i] == 'Empty':
            print("%18s"%'', end='')
        else:
            print("   | ", end='')
            for j in range(0, Nk):
                print("%02x "%D[i][j], end='')
            print("|", end='')
    print('\n')
def AES(InputBytes:str, KeyBytes:str, mode:'E'or'D', Version:'A'or'B'or'C'='A', outType:'state'or'str'='state', out:bool=False, save:bool=False):
    if Version == 'A':
        Nk = 4          # Word 길이
        Nb = Nk*32      # Block 크기
        Nr = 10         # Round 횟수
    elif Version == 'B':
        Nk = 6
        Nb = Nk*32
        Nr = 12
    elif Version == 'C':
        Nk = 8
        Nb = Nk*32
        Nr = 14
    else:
        print("%s의 옵션이 틀렸습니다. :%s"%(sys._getframe().f_code.co_name, Version))
        return -1
    if type(InputBytes) == str:
        I = state(InputBytes, 4)                   # State
    elif type(InputBytes) == state:
        I = InputBytes
    if type(KeyBytes) == str:
        K = keys(state(KeyBytes, Nk), Nk, Nr)            # Key Scheduling
    elif type(KeyBytes) == state:
        K = keys(KeyBytes, Nk, Nr)
    if mode == 'E':
        if out == True:
            print('%s %dBit Encrypting Start: Nk = %1d Nr = %2d\n'%(sys._getframe().f_code.co_name, Nb, Nk, Nr))
        R = [I^K.Stream[0]]                     # Add Round Key + Cipher key
        SB = []
        SR = []
        MC = []
        if save == True:
            R.append(state(Col=Nk))
            SB.append(state(Col=Nk))
            SR.append(state(Col=Nk))
            for i in range(Nr-1):
                R.append(state(Col=Nk))
                SB.append(state(Col=Nk))
                SR.append(state(Col=Nk))
                MC.append(state(Col=Nk))
            for i in range(Nr-1):
                SB[i] = R[i].SubBytes()         # SubBytes
                SR[i] = SB[i].ShiftRows()       # ShiftRows
                MC[i] = SR[i].MixColumns()      # MixColumns
                R[i+1] = MC[i]^K.Stream[i+1]    # Add Round Key + Round key N
            SB[Nr-1] = R[Nr-1].SubBytes()       # SubBytes
            SR[Nr-1] = SB[Nr-1].ShiftRows()     # ShiftRows
            R[Nr] = SR[Nr-1]^K.Stream[Nr]       # Add Round Key + Round key 10
        elif save == False:
            SB.append(state(Col=Nk))
            SR.append(state(Col=Nk))
            MC.append(state(Col=Nk))
            for i in range(Nr-1):
                SB[0] = R[0].SubBytes()         # SubBytes
                SR[0] = SB[0].ShiftRows()       # ShiftRows
                MC[0] = SR[0].MixColumns()      # MixColumns
                R[0] = MC[0]^K.Stream[i+1]      # Add Round Key + Round key N
            SB[0] = R[0].SubBytes()             # SubBytes
            SR[0] = SB[0].ShiftRows()           # ShiftRows
            R[0] = SR[0]^K.Stream[Nr]           # Add Round Key + Round key 10

        if out == True:
            if save == True:
                stetesOut([     'input',            'Empty',            'Empty',            'Empty',            'Key %2d'%0],       I,          state(Col=Nk),  state(Col=Nk),  state(Col=Nk),  K.Stream[0])
                for i in range(Nr-1):
                    stetesOut([ 'Round %2d'%(i+1),  'SubB %2d'%(i+1),   'ShiftR %2d'%(i+1), 'MixC %2d'%(i+1),   'Key %2d'%(i+1)],   R[i],       SB[i],          SR[i],          MC[i],          K.Stream[i+1])
                stetesOut([     'Round %2d'%(Nr),   'SubB %2d'%(Nr),    'ShiftR %2d'%(Nr),  'Empty',            'Key %2d'%Nr],      R[Nr-1],    SB[Nr-1],       SR[Nr-1],       state(Col=Nk),  K.Stream[Nr])
                stetesOut([     'output'], R[Nr])
            else:
                stetesOut([     'input',            'Key',              'output'], I, K.Stream[0], R[0])
        return R[-1].outMain() if outType == 'str' else ( R[-1] if outType == 'state' else -1 )
    elif mode == 'D':
        if out == True:
            print('%s %dbit Decrypting Start: Nk = %1d Nr = %2d\n'%(sys._getframe().f_code.co_name, Nb, Nk, Nr))
        R = [I^K.Stream[Nr]]                    # Add Round Key + Cipher key
        SB = []
        SR = []
        MC = []
        if save == True:
            R.append(state(Col=Nk))
            SB.append(state(Col=Nk))
            SR.append(state(Col=Nk))
            for i in range(Nr-1):
                R.append(state(Col=Nk))
                SB.append(state(Col=Nk))
                SR.append(state(Col=Nk))
                MC.append(state(Col=Nk))
            SR[0] = R[0].InvShiftRows()         # InvShiftRows
            for i in range(Nr-1):
                SB[i] = SR[i].InvSubBytes()     # InvSubBytes
                R[i+1] = SB[i]^K.Stream[Nr-i-1] # Add Round Key + Round key Nr-N
                MC[i] = R[i+1].InvMixColumns()  # InvMixColumns
                SR[i+1] = MC[i].InvShiftRows()  # InvShiftRows
            SB[Nr-1] = SR[Nr-1].InvSubBytes()   # InvSubBytes
            R[Nr] = SB[Nr-1]^K.Stream[0]        # Add Round Key + Round key 0
        elif save == False:
            SB.append(state(Col=Nk))
            SR.append(state(Col=Nk))
            MC.append(state(Col=Nk))
            SR[0] = R[0].InvShiftRows()         # InvShiftRows
            for i in range(Nr-1):
                SB[0] = SR[0].InvSubBytes()     # InvSubBytes
                R[0] = SB[0]^K.Stream[Nr-(i+1)] # Add Round Key + Round key Nr-N
                MC[0] = R[0].InvMixColumns()    # InvMixColumns
                SR[0] = MC[0].InvShiftRows()    # InvShiftRows
            SB[0] = SR[0].InvSubBytes()         # InvSubBytes
            R[0] = SB[0]^K.Stream[0]            # Add Round Key + Round key 0
        
        if out == True:
            if save == True:
                stetesOut([     'input',            'Empty',            'Empty',                'Empty',            'Key %2d'%0],       I,      state(Col=Nk),    state(Col=Nk),    state(Col=Nk),    K.Stream[Nr])
                stetesOut([     'Round %2d'%1,      'Empty',            'I ShiftR %2d'%1,       'I SubB %2d'%1,     'I Key %2d'%1],     R[0],   state(Col=Nk),    SR[0],      SB[0],      K.Stream[Nr-1])
                for i in range(Nr-1):
                    stetesOut([ 'Round %2d'%(i+2),  'I MixC %2d'%(i+2), 'I ShiftR %2d'%(i+2),   'I SubB %2d'%(i+2), 'I Key %2d'%(i+2)], R[i+1], MC[i],      SR[i+1],    SB[i+1],    K.Stream[Nr-(i+2)])
                stetesOut([     'output'], R[Nr])
            else:
                stetesOut([     'input',            'Key',              'output'], I, K.Stream[0], R[0])
        return R[-1].outMain() if outType == 'str' else ( R[-1] if outType == 'state' else -1 )
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

def MixP(Mix:int, X:int): # 원래라면 순서는 상관없지만 Mix에 작은 수를 넣는 게 파악이 편하다.
    ''' 
    GF = [0, 0, 0, 0]
    GF[0] = Mix%2**1
    GF[1] = (Mix%2**2)//2**1
    GF[2] = (Mix%2**3)//2**2
    GF[3] = Mix//2**3
    result = 0
    for i in range(len(GF)):
        tX = X % 0x100 if (X%2**(8-i))//2**(7-i) == 0 else (X%0x100) ^ 0x1b
        GF[i] *= 2**i*tX
        result ^= GF[i]
    return result'''
    result = 0
    for i in range(8):
        if Mix & 1: result ^= X
        K = X & 0x80
        X <<= 1
        # keeresult a 8 bit
        X &= 0xFF
        if K:
            X ^= 0x1b
        Mix >>= 1
    return result
class state:
    def __init__(self, initValue:str="", Col:int=4):
        S = []
        if initValue.find(" ") == -1:
            for i in range(len(initValue)//2):
                S.append(initValue[i*2:i*2+2])
        else:
            S = initValue.split()
        while len(S) < Col*4:  # 패딩: 남는 부분 0으로 채우기
            S.append('0')
        
        self.STATE = []
        for i in range(Col*4):
            if i%Col == 0:
                self.STATE.append([])
                self.STATE[i//Col].append(0x00)
            else:
                self.STATE[i//Col].append(0x00)
        for i in range(0, Col):
            self.STATE[0][i] = int(S[i*4+0], 16)
            self.STATE[1][i] = int(S[i*4+1], 16)
            self.STATE[2][i] = int(S[i*4+2], 16)
            self.STATE[3][i] = int(S[i*4+3], 16)
    def __xor__(self, otherState):  #otherState 타입 체크 하고싶은데 자기자신이라 정의가 안됨. 어떻게 해결하지?
        Nk = len(self.STATE[0])
        if len(otherState.STATE[0]) != Nk:
            print("StateXOR: Fail - Column not same")
            return -1
        else:
            newState = state(Col=len(self.STATE[0]))
            for i in range(4):
                for j in range(Nk):
                    newState.STATE[i][j] = self.STATE[i][j] ^ otherState.STATE[i][j]
            return newState
    def __eq__(self, otherState):
        Nk = len(self.STATE[0])
        if len(otherState.STATE[0]) != Nk:
            print("StateEQ: Fail - Column not same")
            return -1
        else:
            result = True
            for i in range(4):
                for j in range(Nk):
                    k = self.STATE[i][j] == otherState.STATE[i][j]
                    result &= k
            return result
    def outMain(self, out:bool=False, between:str=" "):
        Nk = len(self.STATE[0])
        tmp = ""
        for i in range(Nk):
            for j in range(4):
                tmp = between.join(tmp, hex(self.STATE[i][j])[2:])
        if out == True:
            print(tmp)
        return tmp
    def SubBytes(self):
        Nk = len(self.STATE[0])
        newState = state(Col=Nk)
        for i in range(4):
            for j in range(Nk):
                newState.STATE[i][j] = Table.Sbox[self.STATE[i][j]]
        return newState
    def InvSubBytes(self):
        Nk = len(self.STATE[0])
        newState = state(Col=Nk)
        for i in range(4):
            for j in range(Nk):
                newState.STATE[i][j] = Table.Ibox[self.STATE[i][j]]
        return newState
    def ShiftRows(self):
        Nk = len(self.STATE[0])
        newState = state(Col=Nk)
        for i in range(4):
            for j in range(Nk):
                newState.STATE[i][(j-i)%4] = self.STATE[i][j]
        return newState
    def InvShiftRows(self):
        Nk = len(self.STATE[0])
        newState = state(Col=Nk)
        for i in range(4):
            for j in range(Nk):
                newState.STATE[i][j] = self.STATE[i][(j-i)%4]
        return newState
    def MixColumns(self):   # bin(Mix원소)의 1의 수만큼 쉬프트 연산 후 모두 xor. 예를 들어 3(2^1 + 2^0)이라면 1칸쉬프트(*2^1)와 0칸 쉬프트(*2*0)를 xor한다.
        Nk = len(self.STATE[0])
        newState = state(Col=Nk)
        for i in range(Nk):
            newState.STATE[0][i] = MixP( 0x02, self.STATE[0][i]) ^ MixP( 0x03, self.STATE[1][i]) ^ MixP( 0x01, self.STATE[2][i]) ^ MixP( 0x01, self.STATE[3][i])
            newState.STATE[1][i] = MixP( 0x01, self.STATE[0][i]) ^ MixP( 0x02, self.STATE[1][i]) ^ MixP( 0x03, self.STATE[2][i]) ^ MixP( 0x01, self.STATE[3][i])
            newState.STATE[2][i] = MixP( 0x01, self.STATE[0][i]) ^ MixP( 0x01, self.STATE[1][i]) ^ MixP( 0x02, self.STATE[2][i]) ^ MixP( 0x03, self.STATE[3][i])
            newState.STATE[3][i] = MixP( 0x03, self.STATE[0][i]) ^ MixP( 0x01, self.STATE[1][i]) ^ MixP( 0x01, self.STATE[2][i]) ^ MixP( 0x02, self.STATE[3][i])
        return newState
    def InvMixColumns(self):
        Nk = len(self.STATE[0])
        newState = state(Col=Nk)
        for i in range(Nk):
            newState.STATE[0][i] = MixP( 0x0e, self.STATE[0][i]) ^ MixP( 0x0b, self.STATE[1][i]) ^ MixP( 0x0d, self.STATE[2][i]) ^ MixP( 0x09, self.STATE[3][i])
            newState.STATE[1][i] = MixP( 0x09, self.STATE[0][i]) ^ MixP( 0x0e, self.STATE[1][i]) ^ MixP( 0x0b, self.STATE[2][i]) ^ MixP( 0x0d, self.STATE[3][i])
            newState.STATE[2][i] = MixP( 0x0d, self.STATE[0][i]) ^ MixP( 0x09, self.STATE[1][i]) ^ MixP( 0x0e, self.STATE[2][i]) ^ MixP( 0x0b, self.STATE[3][i])
            newState.STATE[3][i] = MixP( 0x0b, self.STATE[0][i]) ^ MixP( 0x0d, self.STATE[1][i]) ^ MixP( 0x09, self.STATE[2][i]) ^ MixP( 0x0e, self.STATE[3][i])
        return newState

class keys: # 복호화 시엔 적용순서만 반대로. K.Stream[10] ~ [0]
    def __init__(self, initValue:state, Nk:int, Nr:int):
        self.Stream = []
        for r in range(Nr+1):
            self.Stream.append(state(Col=4))    # 들어온 초기값과 관계없이 각 라운트 키는 128bit. 즉 4개의 워드이다.
        for r in range(0, (Nr+1)*4):    # Nr*4 각 스트림(라운드)키는 4개의 워드이므로 라운드수에 4를 곱한다. //아래에서는 한 워드씩 처리해준다.
            # r//4는 각 라운드 수, r%4는 각 라운드 키의 열 위치.
            if r < Nk:              # 초기 키 삽입
                self.Stream[r//4].STATE[0][r%4] = initValue.STATE[0][r]
                self.Stream[r//4].STATE[1][r%4] = initValue.STATE[1][r]
                self.Stream[r//4].STATE[2][r%4] = initValue.STATE[2][r]
                self.Stream[r//4].STATE[3][r%4] = initValue.STATE[3][r]
            elif r % Nk == 0:       # Rcon 곱해야 할 때.
                self.Stream[r//4].STATE[0][r%4] = self.Stream[(r-Nk)//4].STATE[0][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[1][(r-1)%4]] ^ Table.Rcon[(r//Nk)-1]
                self.Stream[r//4].STATE[1][r%4] = self.Stream[(r-Nk)//4].STATE[1][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[2][(r-1)%4]]
                self.Stream[r//4].STATE[2][r%4] = self.Stream[(r-Nk)//4].STATE[2][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[3][(r-1)%4]]
                self.Stream[r//4].STATE[3][r%4] = self.Stream[(r-Nk)//4].STATE[3][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[0][(r-1)%4]]
            else:
                if Nk == 8 and r%Nk == 4:  # 256bit의 경우엔 특수하게 Rcon을 하지 않는 각 라운드 첫 워드를 만들 때, 직전 값에 S-box를 한번 더 해준다.
                    self.Stream[r//4].STATE[0][r%4] = self.Stream[(r-Nk)//4].STATE[0][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[0][(r-1)%4]]
                    self.Stream[r//4].STATE[1][r%4] = self.Stream[(r-Nk)//4].STATE[1][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[1][(r-1)%4]]
                    self.Stream[r//4].STATE[2][r%4] = self.Stream[(r-Nk)//4].STATE[2][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[2][(r-1)%4]]
                    self.Stream[r//4].STATE[3][r%4] = self.Stream[(r-Nk)//4].STATE[3][(r-Nk)%4] ^ Table.Sbox[self.Stream[(r-1)//4].STATE[3][(r-1)%4]]
                else:
                    self.Stream[r//4].STATE[0][r%4] = self.Stream[(r-Nk)//4].STATE[0][(r-Nk)%4] ^ self.Stream[(r-1)//4].STATE[0][(r-1)%4]
                    self.Stream[r//4].STATE[1][r%4] = self.Stream[(r-Nk)//4].STATE[1][(r-Nk)%4] ^ self.Stream[(r-1)//4].STATE[1][(r-1)%4]
                    self.Stream[r//4].STATE[2][r%4] = self.Stream[(r-Nk)//4].STATE[2][(r-Nk)%4] ^ self.Stream[(r-1)//4].STATE[2][(r-1)%4]
                    self.Stream[r//4].STATE[3][r%4] = self.Stream[(r-Nk)//4].STATE[3][(r-Nk)%4] ^ self.Stream[(r-1)//4].STATE[3][(r-1)%4]

def main():
    #128bit
    #Plain   = state("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34", 4)
    #Key     = state("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c", 4)
    #ExC     = state("39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32", 4)
    #T       = 'A'
    #Plain   = state("00112233445566778899aabbccddeeff", 4)
    #Key     = state("000102030405060708090a0b0c0d0e0f", 4)
    #ExC     = state("69c4e0d86a7b0430d8cdb78070b4c55a", 4)
    #T       = 'A'
    
    #192bit
    #Plain   = state("00112233445566778899aabbccddeeff", 4)
    #Key     = state("000102030405060708090a0b0c0d0e0f1011121314151617", 6)
    #ExC     = state("dda97ca4864cdfe06eaf70a0ec0d7191", 4)
    #T       = 'B'

    #256bit
    Plain   = state("00112233445566778899aabbccddeeff", 4)
    Key     = state("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 8)
    ExC     = state("8ea2b7ca516745bfeafc49904b496089", 4)
    T       = 'C'
    #Key     = state("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 8)
    

    Cipher  = AES(Plain, Key, 'E', T, out=False, save=True)
    if ExC == Cipher:
        print("AES 암호화 성공")
    else:
        print("암호화 실패")
        stetesOut(['ExC', 'Cipher'], ExC, Cipher)
    Decrypt = AES(Cipher, Key, 'D', T, out=False, save=False)
    if Decrypt == Plain:
        print("AES 구현 성공")
    else:
        print("구현 실패")
        stetesOut(['Key', 'Plain', 'ExC', 'Cipher', 'Decrypt'], Key, Plain, ExC, Cipher, Decrypt)

if __name__ == "__main__":
    main()
