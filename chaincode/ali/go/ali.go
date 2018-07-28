package main

import (
    "crypto/aes"
    "encoding/json"
    "fmt"
    "bytes"

    "github.com/hyperledger/fabric/core/chaincode/shim"
    "github.com/hyperledger/fabric/bccsp/sw"
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

// map use to record put status
var writemap map[string]interface{}
var acc = 1

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
    }

    userID := args[1]

    // get original data
    orgobj := writemap[userID]
    var orgarray []interface{}
    if orgobj != nil {
        orgmap := orgobj.(map[string]interface{})
        if orgmap["encrypted"] == "no" {
            orgarray = (orgmap["data"]).([]interface{})
            //return shim.Error("Encrypted record has been added!")
        }
        for _, el := range orgarray {
            elmap := el.(Record)
            if elmap.Year == args[2] {
                return shim.Success(nil)
            }
        }
    }

    var record = Record{ID: args[1], Year: args[2], Institute: args[3], Position: args[4]}
    orgarray = append(orgarray, record)
    recordAsBytes, _ := json.Marshal(orgarray)
    APIstub.PutState(userID, recordAsBytes)

    // update local store
    datamap := make(map[string]interface{})
    datamap["data"] = orgarray
    datamap["encrypted"] = "no"
    writemap[userID] = datamap

    return shim.Success(nil)
}

func (s *SmartContract) getRecord(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
    if len(args) != 3 {
        return shim.Error("Incorrect number of arguments. Expecting 3")
    }

    orgbytes, _ := APIstub.GetState(args[1])
    if orgbytes == nil {
        return shim.Success(nil)
    }
    var orgarray []interface{}
    var institute interface{}
    if err := json.Unmarshal(orgbytes, &orgarray); err != nil {
        return shim.Error("Get record failed!")
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
    if len(args) != 5 {
        return shim.Error("Incorrect number of arguments. Expecting 5")
    }
    // get key and iv
    encryptKV, err := APIstub.GetTransient()
    if err != nil {
        return shim.Error("Get transient failed!")
    }
    key := GetKey(encryptKV["ENCKEY"])
    iv := GetIV(encryptKV["IV"])

    userID := args[1]

    // get previous records
    orgobj := writemap[userID]
    var orgarray []interface{}
    if orgobj != nil {
        orgmap := orgobj.(map[string]interface{})
        if orgmap["encrypted"] == "yes" {
            orgarray = (orgmap["data"]).([]interface{})
            //return shim.Error("Record cannot be decrypted!")
        }
        for _, el := range orgarray {
            elmap := el.(Record)
            if elmap.Year == args[2] {
                return shim.Success(nil)
            }
        }
    }

    // add new record
    record := Record{ID: args[1], Year: args[2], Institute: args[3], Position: args[4]}
    orgarray = append(orgarray, record)
    orgarrayAsBytes, _ := json.Marshal(orgarray)
    ciphertext, err := sw.AESCBCPKCS7EncryptWithIV(iv, key, orgarrayAsBytes)
    if err != nil {
        return shim.Error("encrypt record failed")
    }
    APIstub.PutState(userID, ciphertext)

    // store local map data
    datamap := make(map[string]interface{})
    datamap["data"] = orgarray
    datamap["encrypted"] = "yes"
    writemap[userID] = datamap

    return shim.Success(nil)
}

func (s *SmartContract) decRecord(APIstub shim.ChaincodeStubInterface, args[]string) sc.Response {
    if len(args) != 3 {
        return shim.Error("Incorrect number of arguments. Expecting 3")
    }

    ciphertext, _ := APIstub.GetState(args[1])
    if ciphertext == nil {
        return shim.Success(nil)
    }

    // get decrypt key and iv
    decryptKV, err := APIstub.GetTransient()
    if err != nil {
        return shim.Error("Get transient failed!")
    }
    key := GetKey(decryptKV["DECKEY"])

    // decrpyt ciphertext
    plaintext, err := sw.AESCBCPKCS7Decrypt(key, ciphertext)
    if err != nil {
        return shim.Error("Decrypt record failed!")
    }

    // get record according to year
    var plainarray []interface{}
    if err = json.Unmarshal(plaintext, &plainarray); err != nil {
        return shim.Error("Unmarshal record failed!")
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

func GetIV(iv []byte) []byte {
    if len(iv) >= aes.BlockSize {
        iv = iv[0:aes.BlockSize]
    } else {
        iv = ZeroPadding(iv, aes.BlockSize)
    }
    return iv
}

func GetKey(key []byte) []byte {
    if len(key) >= 32 {
        key = key[0:32]
    } else {
        key = ZeroPadding(key, 32)
    }
    return key
}

func ZeroPadding(text []byte, blockSize int) []byte {
    padding := blockSize - len(text)%blockSize
    padtext := bytes.Repeat([]byte{0}, padding)
    return append(text, padtext...)
}

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
    return shim.Success(nil)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

    writemap = make(map[string]interface{})
    // Create a new Smart Contract
    err := shim.Start(new(SmartContract))
    if err != nil {
        fmt.Printf("Error creating new Smart Contract: %s", err)
    }
}
