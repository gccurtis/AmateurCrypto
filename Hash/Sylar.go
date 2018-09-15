package Sylar

import(
/*"fmt"
"os"
"log"
"time"*/
)

func main(){
	
        /*start := time.Now()
	//var inp []byte = []byte{ 34,68,146, 19, 246, 243, 0, 0, 0, 0,0,00,0,0,0,0,0,0 }
	var inp []byte = []byte("0bmvhkjbkfhcgvbn .kjhbcvyukj,mbfyhgcvbhgnbvjhbn;kbxrytughulkbcvhjb gdrtl[pdpbdfznfzdflk'gbtoij;VEjeigjm ofnbnv oiefnucj qb87of4yr3h9g72bv wrr3h9 gu5h4h 0g578q--q[ aghrkmb 402ut8ay 02[4q3 yu[[5 u[u9um 9h iob[[h]try[8tihogfnboihgns[hbfn [a43uat9rihojnhflnklbrmr ;ALHRGOIINZGagh98uy57t84g[ ]q90yihgnb 4ntmgtboirjyg[4089yh5trxxxxxxxxsfdgkfcdfgv uygjhnlyugkh")
	//var hash_out []byte = Hash(inp)
	Hash(inp)
        elapsed := time.Since(start)
        log.Printf("Time elapsed %s",elapsed)
	//fmt.Println(hash_out)
	//fmt.Println(len(hash_out))
	fmt.Println(len(inp))
	/*
	start := time.Now()
	HashFile("read.txt","readHash")
	elapsed := time.Since(start)
  	log.Printf("Time elapsed %s",elapsed)
  	*/
}

/*func HashFile(filename,out string){
	var internal_state []byte = []byte{ 79, 71, 103, 204, 48, 252, 209, 213, 80, 54, 109, 139, 48, 238, 204, 247, 21, 132, 236, 167, 168, 25, 130, 115, 29, 70, 131, 69, 18, 182, 165, 170 }
	var i int
	var err error
	var file *os.File
	file,err = os.Open(filename)
	handle(err)
	var outfile *os.File
	outfile,err = os.Create(out)
	handle(err)
	var inp []byte = make([]byte,32)
	i,_ = file.Read(inp)
	for{
		if i != 0 {
		  	internal_state = hash(inp,internal_state)
		  	i,_ = file.Read(inp)
		}else{
			outfile.Write(internal_state)
			file.Close()
			outfile.Close()
			os.Exit(0)
		}
	}
}

func handle(e error){
	if e != nil{
		fmt.Println(e)
		os.Exit(1)
	}
}*/

func Hash(inp []byte)([]byte){
	var internal_state []byte = []byte{ 79, 71, 103, 204, 48, 252, 209, 213, 80, 54, 109, 139, 48, 238, 204, 247, 21, 132, 236, 167, 168, 25, 130, 115, 29, 70, 131, 69, 18, 182, 165, 170 }
	var b []byte
	for{
		if len(inp) < 32{
		  	internal_state = hash(inp,internal_state)
			return internal_state
		}else{
		  b = inp[:32]
		  inp = inp[32:]
			internal_state = hash(b,internal_state)
		}
	}
}

func hash(inp []byte,internal_state []byte)([]byte){
	var h byte
	var overseer byte = byte(42)
	var alt_state []byte = []byte{ 57, 254, 139, 73, 251, 119, 8, 63, 235, 238, 37, 83, 195, 120, 67, 24, 135, 76, 183, 159, 69, 16, 126, 24, 115, 81, 47, 189, 73, 49, 125, 98 }
	var cbo []byte = []byte{ 174, 48, 51, 86, 97, 146, 109, 141, 217, 164, 93, 34, 233, 10, 69, 34, 39, 216, 213, 155, 47, 109, 172, 107, 29, 139, 213, 191, 200, 246, 208, 160, 138, 198, 143, 4, 255, 186, 91, 17, 68, 50, 27, 96, 208, 232, 120, 172, 220, 76, 31, 160, 218, 125, 36, 102, 154, 81, 64, 59, 42, 129, 98, 93, 249, 178, 23, 39, 206, 171, 73, 76, 131, 232, 116, 240, 75, 130, 153, 148, 130, 220, 216, 142, 120, 186, 35, 182, 61, 232, 155, 150, 230, 184, 38, 162, 129, 16, 58 ,182, 170, 125, 176, 223, 37, 72, 146, 112, 76, 192, 190, 30, 116, 69, 179, 238, 15, 133, 62, 186, 230, 47, 2, 49, 171, 53, 184, 135, 152, 95, 151, 124, 187, 46, 117, 207, 65, 138, 235, 92, 157, 211, 47, 142, 82, 253, 205, 86, 69, 136, 23, 92, 110, 100, 8, 232, 129, 171, 109, 231, 44, 87, 79, 113, 115, 215, 128, 249, 214, 159, 144, 140, 93, 12, 112, 85, 83, 187, 164, 3, 119, 205, 179, 61, 158, 19, 162, 116, 5, 23, 167, 230, 210, 60, 167, 152, 81, 238, 6, 236, 179, 154, 76, 112, 191, 1, 185, 126, 201, 204, 254, 144, 58, 232, 158, 63, 114, 147, 143, 8, 46, 3, 228, 197, 226, 60, 191, 115, 34, 212, 119, 253, 152, 202, 255, 232, 49, 23, 126, 245, 148, 3, 131, 209, 18, 15, 34, 109, 228, 25, 189, 172, 201, 203, 247, 103 }
	for len(inp) != 32{
		inp = append(inp,alt_state[len(inp)])
	}
	for x:=0;x<32;x++{
		h = inp[x]
		inp[x] = overseer^inp[x]
		overseer = 255^(cbo[overseer]+h)
		internal_state[x] = internal_state[x]^overseer
	}
	for i:=0;i<10;i++{
		for x:=0;x<32;x++{
			h = cbo[inp[x]+internal_state[x]]
			inp[x] = (overseer^inp[x])+internal_state[x]
			overseer = 255^(cbo[overseer]+h)
		}
	}
	return inp
}
