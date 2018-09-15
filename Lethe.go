package Lethe

import(
  //"fmt"
  //"time"
  //"log"
  )

func main(){
  //start := time.Now()
  //p := []byte("1234567890123456")
  //k := []byte("12345678901234567890123456789012")
  //d := Encrypt(p,k)
  //fmt.Println(d)
  //q := Decrypt(d,k)
  //fmt.Println(string(q))
  //Encrypt(p,k)
  //elapsed := time.Since(start)
  //log.Printf("%s",elapsed)
}

func right_shift(inp byte, num byte)(byte){
  num = num%8
  for{
    if num > 0{
      if inp%2 != 0{
        inp = (inp>>1)+128
        num--
      }else{
        inp >>= 1
        num--
      }
    }else{
      return inp
    }
  }
}

func whiten(subkey []byte,n int,subkey2 []byte)([]byte){
  var ret []byte = make([]byte,16)
  var t []byte = []byte{185,79,174,67,15,16,35,148,28,251,226,48,77,180,45,97,161,123,144,239,192,115,184,208,49,3,139,25,56,150,19,130,193,27,141,133,165,135,50,40,244,194,118,114,29,134,203,54,176,229,39,178,113,187,42,166,224,227,23,44,173,245,51,10,230,158,170,188,12,81,211,90,186,200,253,167,70,36,31,204,85,11,46,107,109,62,237,119,24,47,195,61,74,106,30,68,129,182,121,86,98,33,34,22,55,228,252,111,160,190,140,94,169,199,0,63,163,232,242,84,177,157,75,116,69,238,222,88,154,131,212,38,205,93,221,72,255,183,9,76,233,198,179,101,216,146,52,57,231,80,8,210,13,142,191,213,18,249,151,168,136,196,147,110,82,159,218,206,215,149,5,250,37,20,181,145,64,66,73,201,2,103,223,89,117,248,112,153,162,4,6,225,128,104,1,41,217,219,92,143,164,65,156,246,100,209,87,125,152,99,137,102,132,197,122,108,207,14,247,138,95,235,7,175,127,243,240,254,17,172,105,71,155,78,236,59,189,21,214,43,234,202,126,58,124,220,171,83,53,60,96,26,32,241,91,120}
  for ind,val := range subkey{
    ret[(ind+n)%16] = t[right_shift(val,byte(n))]+subkey2[ind]
  }
  return ret
}

func Encrypt(Plaintext, Key []byte)([]byte){
  var l int = len(Plaintext)
  if l%16 != 0{
    return Plaintext
  }
  var ciphertext []byte = make([]byte,l)
  var tmp []byte = make([]byte,16)
  var sub1 []byte = Key[0:16]
  var sub2 []byte = Key[16:32]
  //fmt.Println(string(sub1),":1 2:",string(sub2))
  var subs [][]byte = make([][]byte,5)
  for i:=0;i<5;i++{
    if i%2!=0{
      sub1 = whiten(sub1,i,sub2)
      subs[i] = sub1
    }else{
      sub2 = whiten(sub2,i,sub1)
      subs[i] = sub2
    }
  }
  for i:=0;i<l;i+=16{
    //fmt.Println("enc")
    tmp = Plaintext[i:i+16]
    for e:=0;e<5;e++{
      tmp = transition(tmp)
      if e%2==0{
        //fmt.Println("key",subs[e])
        tmp = columnField(tmp,subs[e])
        //fmt.Println("odd,col",tmp)
        tmp = rowField(tmp,subs[e])
        //fmt.Println("odd,row",tmp)
      }else{
        //fmt.Println("key",subs[e])
        tmp = rowField(tmp,subs[e])
        //fmt.Println("even,row",tmp)
        tmp = columnField(tmp,subs[e])
        //fmt.Println("even,col",tmp)
      }
    }
    ciphertext = extend(ciphertext,tmp,i)
    //fmt.Println("end",tmp)
  }
  return ciphertext
}

func Decrypt(Ciphertext, Key []byte)([]byte){
  var l int = len(Ciphertext)
  if l%16 != 0{
    return Ciphertext
  }
  var plaintext []byte = make([]byte,l)
  var tmp []byte = make([]byte,16)
  var sub1 []byte = Key[0:16]
  var sub2 []byte = Key[16:32]
  //fmt.Println(string(sub1),":1 2:",string(sub2))
  var subs [][]byte = make([][]byte,5)
  for i:=0;i<5;i++{
    if i%2!=0{
      sub1 = whiten(sub1,i,sub2)
      subs[i] = sub1
    }else{
      sub2 = whiten(sub2,i,sub1)
      subs[i] = sub2
    }
  }
  for i:=0;i<l;i+=16{
    //fmt.Println("dec")
    tmp = Ciphertext[i:i+16]
    for e:=4;e>-1;e--{
      if e%2==0{
        //fmt.Println("key",subs[e])
        tmp = invRowField(tmp,subs[e])
        //fmt.Println("odd,irow",tmp)
        tmp = invColumnField(tmp,subs[e])
        //fmt.Println("odd,icol",tmp)
      }else{
        //fmt.Println("key",subs[e])
        tmp = invColumnField(tmp,subs[e])
        //fmt.Println("even,icol",tmp)
        tmp = invRowField(tmp,subs[e])
        //fmt.Println("even,irow",tmp)
      }
      tmp = inverseTransition(tmp)
    }
    plaintext = extend(plaintext,tmp,i)
    //fmt.Println("end",tmp)
  }
  return plaintext
}
func extend(f,s []byte,start int)([]byte){
  for ind,val := range(s){
    f[start+ind] = val
  }
  return f
}

func forwardPropagate(init byte,sli []byte)([]byte){
  var ret []byte = make([]byte,4)
  for i:=0;i<4;i++{
    ret[i] = sli[i]^init
    init = sli[i]+init
  }
  return ret
}
func backwardPropagate(init byte,sli []byte)([]byte){
  var ret []byte = make([]byte,4)
  for i:=3;i>=0;i--{
    ret[i] = sli[i]^init
    init = sli[i]+init
  }
  return ret
}
func invForwardPropagate(init byte,sli []byte)([]byte){
  var ret []byte = make([]byte,4)
  for i:=0;i<4;i++{
    ret[i] = sli[i]^init
    init = ret[i]+init
  }
  return ret
}
func invBackwardPropagate(init byte,sli []byte)([]byte){
  var ret []byte = make([]byte,4)
  for i:=3;i>=0;i--{
    ret[i] = sli[i]^init
    init = ret[i]+init
  }
  return ret
}
func doublePropagation(p,subkey []byte)(byte,byte,byte,byte){
  var ret []byte = make([]byte,4)
  ret = forwardPropagate(subkey[0],p)
  ret = backwardPropagate(subkey[1],ret)
  return ret[0],ret[1],ret[2],ret[3]
}
func invDoublePropagation(p,subkey []byte)(byte,byte,byte,byte){
  var ret []byte = make([]byte,len(p))
  ret = invBackwardPropagate(subkey[1],p)
  ret = invForwardPropagate(subkey[0],ret)
  return ret[0],ret[1],ret[2],ret[3]
}

func rowField(plaintext, subkey []byte)([]byte){
  /*var w []byte = plaintext[0:4]
  var x []byte = plaintext[4:8]
  var y []byte = plaintext[8:12]
  var z []byte = plaintext[12:16]*/

  plaintext[0],plaintext[1],plaintext[2],plaintext[3] = doublePropagation([]byte{plaintext[0],plaintext[1],plaintext[2],plaintext[3]},subkey[0:2])
  plaintext[4],plaintext[5],plaintext[6],plaintext[7] = doublePropagation([]byte{plaintext[4],plaintext[5],plaintext[6],plaintext[7]},subkey[2:4])
  plaintext[8],plaintext[9],plaintext[10],plaintext[11] = doublePropagation([]byte{plaintext[8],plaintext[9],plaintext[10],plaintext[11]},subkey[4:6])
  plaintext[12],plaintext[13],plaintext[14],plaintext[15] = doublePropagation([]byte{plaintext[12],plaintext[13],plaintext[14],plaintext[15]},subkey[6:8])

  plaintext[0],plaintext[4],plaintext[8],plaintext[12] = doublePropagation([]byte{plaintext[0],plaintext[4],plaintext[8],plaintext[12]},subkey[8:10])
  plaintext[1],plaintext[5],plaintext[9],plaintext[13] = doublePropagation([]byte{plaintext[1],plaintext[5],plaintext[9],plaintext[13]},subkey[10:12])
  plaintext[2],plaintext[6],plaintext[10],plaintext[14] = doublePropagation([]byte{plaintext[2],plaintext[6],plaintext[10],plaintext[14]},subkey[12:14])
  plaintext[3],plaintext[7],plaintext[11],plaintext[15] = doublePropagation([]byte{plaintext[3],plaintext[7],plaintext[11],plaintext[15]},subkey[14:16])
  return plaintext
}

func columnField(plaintext, subkey []byte)([]byte){
  /*var w []byte = plaintext[0:4]
  var x []byte = plaintext[4:8]
  var y []byte = plaintext[8:12]
  var z []byte = plaintext[12:16]*/

  plaintext[0],plaintext[4],plaintext[8],plaintext[12] = doublePropagation([]byte{plaintext[0],plaintext[4],plaintext[8],plaintext[12]},subkey[0:2])
  plaintext[1],plaintext[5],plaintext[9],plaintext[13] = doublePropagation([]byte{plaintext[1],plaintext[5],plaintext[9],plaintext[13]},subkey[2:4])
  plaintext[2],plaintext[6],plaintext[10],plaintext[14] = doublePropagation([]byte{plaintext[2],plaintext[6],plaintext[10],plaintext[14]},subkey[4:6])
  plaintext[3],plaintext[7],plaintext[11],plaintext[15] = doublePropagation([]byte{plaintext[3],plaintext[7],plaintext[11],plaintext[15]},subkey[6:8])

  plaintext[0],plaintext[1],plaintext[2],plaintext[3] = doublePropagation([]byte{plaintext[0],plaintext[1],plaintext[2],plaintext[3]},subkey[8:10])
  plaintext[4],plaintext[5],plaintext[6],plaintext[7] = doublePropagation([]byte{plaintext[4],plaintext[5],plaintext[6],plaintext[7]},subkey[10:12])
  plaintext[8],plaintext[9],plaintext[10],plaintext[11] = doublePropagation([]byte{plaintext[8],plaintext[9],plaintext[10],plaintext[11]},subkey[12:14])
  plaintext[12],plaintext[13],plaintext[14],plaintext[15] = doublePropagation([]byte{plaintext[12],plaintext[13],plaintext[14],plaintext[15]},subkey[14:16])

  return plaintext
}

func invRowField(plaintext, subkey []byte)([]byte){
  /*var w []byte = plaintext[0:4]
  var x []byte = plaintext[4:8]
  var y []byte = plaintext[8:12]
  var z []byte = plaintext[12:16]*/

  plaintext[0],plaintext[4],plaintext[8],plaintext[12] = invDoublePropagation([]byte{plaintext[0],plaintext[4],plaintext[8],plaintext[12]},subkey[8:10])
  plaintext[1],plaintext[5],plaintext[9],plaintext[13] = invDoublePropagation([]byte{plaintext[1],plaintext[5],plaintext[9],plaintext[13]},subkey[10:12])
  plaintext[2],plaintext[6],plaintext[10],plaintext[14] = invDoublePropagation([]byte{plaintext[2],plaintext[6],plaintext[10],plaintext[14]},subkey[12:14])
  plaintext[3],plaintext[7],plaintext[11],plaintext[15] = invDoublePropagation([]byte{plaintext[3],plaintext[7],plaintext[11],plaintext[15]},subkey[14:16])

  plaintext[0],plaintext[1],plaintext[2],plaintext[3] = invDoublePropagation([]byte{plaintext[0],plaintext[1],plaintext[2],plaintext[3]},subkey[0:2])
  plaintext[4],plaintext[5],plaintext[6],plaintext[7] = invDoublePropagation([]byte{plaintext[4],plaintext[5],plaintext[6],plaintext[7]},subkey[2:4])
  plaintext[8],plaintext[9],plaintext[10],plaintext[11] = invDoublePropagation([]byte{plaintext[8],plaintext[9],plaintext[10],plaintext[11]},subkey[4:6])
  plaintext[12],plaintext[13],plaintext[14],plaintext[15] = invDoublePropagation([]byte{plaintext[12],plaintext[13],plaintext[14],plaintext[15]},subkey[6:8])

  return plaintext
}

func invColumnField(plaintext, subkey []byte)([]byte){
  /*var w []byte = plaintext[0:4]
  var x []byte = plaintext[4:8]
  var y []byte = plaintext[8:12]
  var z []byte = plaintext[12:16]*/

  plaintext[0],plaintext[1],plaintext[2],plaintext[3] = invDoublePropagation([]byte{plaintext[0],plaintext[1],plaintext[2],plaintext[3]},subkey[8:10])
  plaintext[4],plaintext[5],plaintext[6],plaintext[7] = invDoublePropagation([]byte{plaintext[4],plaintext[5],plaintext[6],plaintext[7]},subkey[10:12])
  plaintext[8],plaintext[9],plaintext[10],plaintext[11] = invDoublePropagation([]byte{plaintext[8],plaintext[9],plaintext[10],plaintext[11]},subkey[12:14])
  plaintext[12],plaintext[13],plaintext[14],plaintext[15] = invDoublePropagation([]byte{plaintext[12],plaintext[13],plaintext[14],plaintext[15]},subkey[14:16])

  plaintext[0],plaintext[4],plaintext[8],plaintext[12] = invDoublePropagation([]byte{plaintext[0],plaintext[4],plaintext[8],plaintext[12]},subkey[0:2])
  plaintext[1],plaintext[5],plaintext[9],plaintext[13] = invDoublePropagation([]byte{plaintext[1],plaintext[5],plaintext[9],plaintext[13]},subkey[2:4])
  plaintext[2],plaintext[6],plaintext[10],plaintext[14] = invDoublePropagation([]byte{plaintext[2],plaintext[6],plaintext[10],plaintext[14]},subkey[4:6])
  plaintext[3],plaintext[7],plaintext[11],plaintext[15] = invDoublePropagation([]byte{plaintext[3],plaintext[7],plaintext[11],plaintext[15]},subkey[6:8])

  return plaintext
}

func transition(plaintext []byte)([]byte){
  var ret []byte = make([]byte,16)
  var cbo1 []byte = []byte{116,217,236,84,31,22,227,12,61,100,172,49,146,250,86,137,185,241,3,159,239,102,98,245,188,44,56,123,117,42,178,55,133,70,8,62,166,147,202,198,50,209,1,0,4,92,104,95,206,228,151,30,118,222,21,148,24,189,6,187,230,88,229,39,54,179,78,145,216,130,134,97,53,111,83,135,113,235,75,195,233,238,132,41,193,119,152,131,115,52,183,36,19,215,180,141,214,212,66,69,33,252,243,71,246,177,199,77,139,79,11,74,169,154,143,192,210,255,91,46,208,161,149,156,223,82,127,16,107,182,67,240,226,244,138,120,106,219,26,57,136,48,99,17,128,5,60,59,14,221,40,165,251,160,125,158,207,142,170,163,29,109,234,173,38,140,197,15,122,204,253,150,81,96,162,35,191,20,47,105,168,68,242,205,218,25,90,184,63,186,64,220,224,194,65,254,249,72,237,51,45,13,32,231,112,167,164,103,87,247,144,174,89,248,211,157,9,203,94,37,80,175,85,129,114,200,213,27,232,34,121,2,124,28,110,18,153,201,155,171,101,43,176,93,58,196,7,225,23,190,76,10,73,126,181,108}
  var cbo2 []byte = []byte{95,81,25,33,45,87,74,20,218,101,195,153,146,28,162,17,65,194,166,2,150,128,172,93,104,66,188,30,3,19,181,129,220,98,177,21,82,252,9,157,248,207,107,178,135,231,154,159,241,200,249,24,175,37,35,141,80,184,7,244,203,36,32,132,71,187,228,10,237,4,210,176,151,143,240,78,113,142,44,55,103,193,214,167,39,236,229,60,48,149,226,114,29,76,216,86,180,170,96,213,190,112,225,245,53,148,144,136,161,34,199,253,122,130,22,201,27,251,109,64,102,56,208,243,160,234,40,31,42,57,138,16,164,8,192,156,67,51,246,227,215,186,99,168,118,59,205,5,79,125,147,83,183,47,140,61,119,127,219,155,75,85,171,152,133,173,204,88,105,165,73,0,206,202,242,49,72,50,134,106,169,255,92,139,191,117,68,232,124,43,110,198,182,126,224,69,52,14,26,18,221,222,13,70,108,91,185,212,179,158,238,120,100,137,189,116,145,230,62,23,94,163,46,217,89,6,90,247,250,121,11,63,174,77,111,38,254,196,209,197,123,223,12,211,233,84,41,15,115,131,54,97,58,1,239,235}
  var cbo3 []byte = []byte{41,52,48,195,110,114,84,29,139,230,145,186,234,151,122,253,6,126,16,49,162,157,255,121,34,131,207,169,138,247,21,83,251,225,97,238,26,175,135,89,161,173,75,87,43,18,174,15,166,36,187,2,242,33,101,71,28,193,73,221,170,240,47,134,92,179,163,180,35,38,226,115,108,209,146,219,42,74,144,143,192,153,194,129,202,17,25,4,1,10,235,128,102,160,72,147,58,190,182,246,137,53,245,127,81,156,218,98,201,56,215,23,64,82,132,37,236,229,70,113,212,111,66,248,80,12,213,112,130,176,154,69,86,241,150,227,148,172,99,149,228,181,24,120,59,77,107,5,7,109,203,249,8,216,223,214,63,9,177,68,94,14,93,220,62,106,183,20,211,30,217,140,32,104,250,51,90,204,136,232,85,237,65,22,205,189,78,200,164,185,165,45,254,119,39,188,79,118,167,50,61,191,100,76,133,88,199,198,233,206,142,124,158,11,57,46,152,159,60,196,125,184,117,96,103,231,171,178,13,55,54,155,197,67,208,123,40,27,224,0,3,91,31,95,243,105,116,210,19,222,239,252,168,44,244,141}
  var cbo4 []byte = []byte{213,192,217,117,183,124,86,212,241,125,35,5,46,136,9,222,154,152,137,235,165,100,49,142,162,109,53,229,115,19,246,95,232,110,155,239,7,167,159,120,105,32,163,40,199,119,28,83,67,164,189,245,219,140,26,87,89,134,60,203,104,61,4,111,198,141,123,244,132,48,102,201,54,77,177,174,14,85,90,158,97,47,205,228,78,214,255,249,55,114,31,21,122,168,79,179,240,145,151,16,208,234,218,178,13,172,20,45,116,93,157,2,24,220,70,15,27,42,193,94,56,144,0,139,148,103,195,99,129,230,224,146,156,175,12,88,248,101,173,11,63,166,161,62,25,51,64,80,130,74,187,169,8,17,131,69,147,253,233,190,44,143,39,71,202,121,243,106,171,112,98,223,81,128,52,34,33,236,237,231,41,176,211,194,238,254,127,160,135,108,57,197,38,252,153,150,22,75,1,149,181,92,29,65,206,180,207,210,242,138,184,170,68,96,107,59,126,118,216,43,82,23,30,3,50,188,204,215,209,6,196,191,36,247,73,66,185,251,226,37,113,76,227,10,182,186,18,133,91,221,58,250,72,200,225,84}

  /*var w []byte = plaintext[0:4]
  var x []byte = plaintext[4:8]
  var y []byte = plaintext[8:12]
  var z []byte = plaintext[12:16]*/

  ret[0] = cbo1[plaintext[3]]
  ret[1] = cbo1[plaintext[6]]
  ret[2] = cbo1[plaintext[9]]
  ret[3] = cbo1[plaintext[12]]

  ret[4] = cbo2[plaintext[2]]
  ret[5] = cbo2[plaintext[5]]
  ret[6] = cbo2[plaintext[8]]
  ret[7] = cbo2[plaintext[15]]

  ret[8] = cbo3[plaintext[1]]
  ret[9] = cbo3[plaintext[4]]
  ret[10] = cbo3[plaintext[11]]
  ret[11] = cbo3[plaintext[14]]

  ret[12] = cbo4[plaintext[0]]
  ret[13] = cbo4[plaintext[7]]
  ret[14] = cbo4[plaintext[10]]
  ret[15] = cbo4[plaintext[13]]
  return ret
}

func inverseTransition(c []byte)([]byte){
  var ret []byte = make([]byte,16)
  var inv_cbo1 []byte = []byte{43,42,231,18,44,145,58,246,34,216,251,110,7,201,148,167,127,143,235,92,177,54,5,248,56,185,138,227,233,160,51,4,202,100,229,175,91,219,164,63,150,83,29,241,25,200,119,178,141,11,40,199,89,72,64,31,26,139,244,147,146,8,35,188,190,194,98,130,181,99,33,103,197,252,111,78,250,107,66,109,220,172,125,74,3,222,14,208,61,212,186,118,45,243,218,47,173,71,22,142,9,240,21,207,46,179,136,128,255,161,234,73,204,76,224,88,0,28,52,85,135,230,168,27,232,154,253,126,144,223,69,87,82,32,70,75,140,15,134,108,165,95,157,114,210,67,12,37,55,122,171,50,86,236,113,238,123,215,155,19,153,121,174,159,206,151,36,205,180,112,158,239,10,163,211,221,242,105,30,65,94,254,129,90,187,16,189,59,24,57,249,176,115,84,193,79,245,166,39,106,225,237,38,217,169,183,48,156,120,41,116,214,97,226,96,93,68,1,184,137,191,149,53,124,192,247,132,6,49,62,60,203,228,80,162,77,2,198,81,20,131,17,182,102,133,23,104,209,213,196,13,152,101,170,195,117}
  var inv_cbo2 []byte = []byte{171,253,19,28,69,147,225,58,133,38,67,230,242,202,197,247,131,15,199,29,7,35,114,219,51,2,198,116,13,92,27,127,62,3,109,54,61,53,235,84,126,246,128,189,78,4,222,153,88,175,177,137,196,104,250,79,121,129,252,145,87,155,218,231,119,16,25,136,186,195,203,64,176,170,6,160,93,233,75,148,56,1,36,151,245,161,95,5,167,224,226,205,182,23,220,0,98,251,33,142,212,9,120,80,24,168,179,42,204,118,190,234,101,76,91,248,215,185,144,156,211,229,112,240,188,149,193,157,21,31,113,249,63,164,178,44,107,213,130,183,154,55,77,73,106,216,12,150,105,89,20,72,163,11,46,159,135,39,209,47,124,108,14,221,132,169,18,83,143,180,97,162,22,165,232,52,71,34,43,208,96,30,192,152,57,206,141,65,26,214,100,184,134,81,17,10,237,239,191,110,49,115,173,60,166,146,172,41,122,238,70,243,207,99,82,140,94,223,8,158,32,200,201,241,194,102,90,139,66,86,217,45,187,244,125,255,85,68,210,254,74,48,174,123,59,103,138,227,40,50,228,117,37,111,236,181}
  var inv_cbo3 []byte = []byte{239,88,51,240,87,147,16,148,152,157,89,213,125,228,161,47,18,85,45,248,167,30,183,111,142,86,36,237,56,7,169,242,172,53,24,68,49,115,69,194,236,0,76,44,253,191,215,62,2,19,199,175,1,101,230,229,109,214,96,144,218,200,164,156,112,182,122,233,159,131,118,55,94,58,77,42,203,145,186,196,124,104,113,31,6,180,132,43,205,39,176,241,64,162,160,243,223,34,107,138,202,54,92,224,173,245,165,146,72,149,4,121,127,119,5,71,246,222,197,193,143,23,14,235,211,220,17,103,91,83,128,25,114,204,63,38,178,100,28,8,171,255,210,79,78,10,74,95,136,139,134,13,216,81,130,231,105,21,212,217,93,40,20,66,188,190,48,198,252,27,60,226,137,41,46,37,129,158,227,65,67,141,98,166,221,189,11,50,195,185,97,201,80,57,82,3,219,232,207,206,187,108,84,150,177,184,209,26,234,73,247,168,120,126,155,110,153,170,106,75,163,59,249,154,238,33,70,135,140,117,9,225,179,208,12,90,116,181,35,250,61,133,52,244,254,102,99,29,123,151,174,32,251,15,192,22}
  var inv_cbo4 []byte = []byte{122,198,111,223,62,11,229,36,152,14,243,139,134,104,76,115,99,153,246,29,106,91,196,221,112,144,54,116,46,202,222,90,41,176,175,10,232,239,192,162,43,180,117,219,160,107,12,81,69,22,224,145,174,26,72,88,120,190,250,215,58,61,143,140,146,203,235,48,212,155,114,163,252,234,149,197,241,73,84,94,147,172,220,47,255,77,6,55,135,56,78,248,201,109,119,31,213,80,170,127,21,137,70,125,60,40,167,214,189,25,33,63,169,240,89,28,108,3,217,45,39,165,92,66,5,9,216,186,173,128,148,154,68,247,57,188,13,18,209,123,53,65,23,161,121,97,131,156,124,199,195,98,17,194,16,34,132,110,79,38,187,142,24,42,49,20,141,37,93,151,211,168,105,138,75,133,181,74,103,95,205,200,244,4,210,236,245,150,225,50,159,231,1,118,183,126,230,191,64,44,253,71,164,59,226,82,204,206,100,228,207,182,7,0,85,227,218,2,102,52,113,249,15,171,130,254,238,242,83,27,129,179,32,158,101,19,177,178,184,35,96,8,208,166,67,51,30,233,136,87,251,237,193,157,185,86}

  /*var w []byte = plaintext[0:4]
  var x []byte = plaintext[4:8]
  var y []byte = plaintext[8:12]
  var z []byte = plaintext[12:16]*/

  ret[3] = inv_cbo1[c[0]]
  ret[6] = inv_cbo1[c[1]]
  ret[9] = inv_cbo1[c[2]]
  ret[12] = inv_cbo1[c[3]]

  ret[2] = inv_cbo2[c[4]]
  ret[5] = inv_cbo2[c[5]]
  ret[8] = inv_cbo2[c[6]]
  ret[15] = inv_cbo2[c[7]]

  ret[1] = inv_cbo3[c[8]]
  ret[4] = inv_cbo3[c[9]]
  ret[11] = inv_cbo3[c[10]]
  ret[14] = inv_cbo3[c[11]]

  ret[0] = inv_cbo4[c[12]]
  ret[7] = inv_cbo4[c[13]]
  ret[10] = inv_cbo4[c[14]]
  ret[13] = inv_cbo4[c[15]]
  return ret
}
