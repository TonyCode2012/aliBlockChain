package main

/* Imports
 * 4 utility libraries for formatting, handling bytes, reading and writing JSON, and string manipulation
 * 2 specific Hyperledger Fabric specific libraries for Smart Contracts
 */
import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/json"
    "fmt"
    "bytes"

    "github.com/hyperledger/fabric/core/chaincode/shim"
    bccsp "github.com/hyperledger/fabric/bccsp"
    sw "github.com/hyperledger/fabric/bccsp/sw"
    sc "github.com/hyperledger/fabric/protos/peer"
)

// Define the Smart Contract structure
type SmartContract struct {
}

// Define the record structure
type Record struct {
    ID          string `json:"id"`
    Year        string `json:"year"`
    Institute   string `json:"institute"`
    Position    string `json:"position"`
}

/*
 * The addRecord method is called to create a new record
 */
func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {
    //args := APIstub.GetFunctionAndParameters()
    args := APIstub.GetStringArgs()
    function := args[0]
    if function == "addRecord" {
        return s.addRecord(APIstub, args)
    } else if function == "getRecord" {
        return s.getRecord(APIstub, args)
    } else if function == "encRecord" {
        return s.encRecord(APIstub, args)
    } else if function == "decRecord" {
        return s.decRecord(APIstub, args)
    }

    return shim.Error("Invalid Smart Contract function name "+function)
}

func (s *SmartContract) addRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
    if len(args) != 5 {
        return shim.Error("Incorrect number of arguments. Expecting 5")
        //return nil
    }

    var record = Record{ID: args[1], Year: args[2], Institute: args[3], Position: args[4]}

    var orgarray []interface{}
    orgRecord, _ := APIstub.GetState(args[1])
    if orgRecord != nil {
        if err := json.Unmarshal(orgRecord, &orgarray); err != nil {
            panic(err)
        }
        for _, el := range orgarray {
            elmap := el.(map[string]interface{})
            if elmap["year"] == args[2] {
                return shim.Success(nil)
                //return nil
            }
        }
    }
    orgarray = append(orgarray, record)
    recordAsBytes, _ := json.Marshal(orgarray)
    APIstub.PutState(args[1], recordAsBytes)

    return shim.Success(nil)
}

func (s *SmartContract) getRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
    if len(args) != 3 {
        return shim.Error("Incorrect number of arguments. Expecting 1")
    }

    orgbytes, _ := APIstub.GetState(args[1])
    if orgbytes == nil {
        return shim.Success(nil)
    }
    var orgarray []interface{}
    var institute interface{}
    if err := json.Unmarshal(orgbytes, &orgarray); err != nil {
        panic(err)
    }
    for _, el := range orgarray {
        elmap := el.(map[string]interface{})
        if elmap["year"] == args[2] {
            institute = elmap["institute"]
            break
        }
    }
    if institute == nil {
        return shim.Success(nil)
    }

    instituteAsBytes, _ := json.Marshal(institute)
    instituteAsBytes = instituteAsBytes[1:len(instituteAsBytes)-1]
    return shim.Success(instituteAsBytes)
}

func (s *SmartContract) encRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
    encryptKV, err := APIstub.GetTransient()
    if err != nil {
        panic(err)
    }
    key := encryptKV["ENCKEY"]
    iv := encryptKV["IV"]

    key = ZeroPadding(key, aes.BlockSize)
    iv = GetIV(iv, aes.BlockSize)

    block, err := aes.NewCipher(key)
    if err != nil {
        panic(err)
    }

    // get previous records
    orgciphertext, _ := APIstub.GetState(args[1])
    var orgarray []interface{}
    if len(orgciphertext) != 0 {
        if len(orgciphertext) % aes.BlockSize != 0 {
            return shim.Error("ciphered text is not a multiple of block size!")
        }
        orgplaintextlen := len(orgciphertext) - aes.BlockSize
        orgplaintext := orgciphertext[:orgplaintextlen]
        decmode := cipher.NewCBCDecrypter(block, iv)
        decmode.CryptBlocks(orgplaintext, orgplaintext)
        orgplaintext = ZeroUnPadding(orgplaintext)
        if err = json.Unmarshal(orgplaintext, &orgarray); err != nil {
            panic(err)
        }
        for _, el := range orgarray {
            elmap := el.(map[string]interface{})
            if elmap["year"] == args[2] {
                return shim.Success(nil)
            }
        }
    }

    // add new record
    record := Record{ID: args[1], Year: args[2], Institute: args[3], Position: args[4]}
    orgarray = append(orgarray, record)
    plaintext, _ := json.Marshal(orgarray)
    plaintext = ZeroPadding(plaintext, aes.BlockSize)

    ciphertext := make([]byte, len(plaintext))
    ciphertext = append(ciphertext, iv...)

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext[:len(plaintext)], plaintext)

    APIstub.PutState(args[1], ciphertext)

    return shim.Success(nil)
}

func (s *SmartContract) decRecord(APIstub shim.ChaincodeStubInterface, args[]string) sc.Response {
    cipherText, _ := APIstub.GetState(args[1])
    if cipherText == nil {
        return shim.Success(nil)
        //return nil
    }

    // get decrypt key and iv
    decryptKV, err := APIstub.GetTransient()
    if err != nil {
        panic(err)
    }
    key := decryptKV["DECKEY"]
    key = ZeroPadding(key, aes.BlockSize)
    plaintextlen := len(cipherText) - aes.BlockSize
    iv := cipherText[plaintextlen:]

    // validate ciphertext
    cipherText = cipherText[:plaintextlen]
    if len(cipherText) < aes.BlockSize {
        panic("cipherText is too short!")
    }
    if len(cipherText) % aes.BlockSize != 0 {
        panic("cipherText is not a multiple of the block size!")
    }

    // decrpyt ciphertext
    block, err := aes.NewCipher(key)
    if err != nil {
        panic(nil)
    }
    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(cipherText, cipherText)
    cipherText = ZeroUnPadding(cipherText)

    // get record according to year
    var plainarray []interface{}
    if err = json.Unmarshal(cipherText, &plainarray); err != nil {
        panic(err)
    }
    for _, el := range plainarray {
        elmap := el.(map[string]interface{})
        if elmap["year"] == args[2] {
            instituteAsBytes, _ := json.Marshal(elmap["institute"])
            instituteAsBytes = instituteAsBytes[1:len(instituteAsBytes)-1]
            return shim.Success(instituteAsBytes)
        }
    }

    return shim.Success(nil)
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{0}, padding)
    return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
    return bytes.TrimFunc(origData,
        func(r rune) bool {
            return r == rune(0)
    })
}

func GetIV(iv []byte, blocksize int) []byte {
    if len(iv) >= blocksize {
        iv = iv[:blocksize]
    } else {
        iv = ZeroPadding(iv, blocksize)
    }
    return iv
}

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
    return shim.Success(nil)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

    // Create a new Smart Contract
    err := shim.Start(new(SmartContract))
    if err != nil {
        fmt.Printf("Error creating new Smart Contract: %s", err)
    }
}
