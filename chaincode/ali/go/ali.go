package main

import (
    "encoding/json"
    "fmt"

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
var writemap map[string][]interface{}

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

    var record = Record{ID: args[1], Year: args[2], Institute: args[3], Position: args[4]}
    orgarray := writemap[userID]
    orgarray = append(orgarray, record)
    recordAsBytes, _ := json.Marshal(orgarray)
    APIstub.PutState(userID, recordAsBytes)
    writemap[userID] = orgarray
    return shim.Success(recordAsBytes)

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
    key, _ := json.Marshal(encryptKV["ENCKEY"])
    iv, _ := json.Marshal(encryptKV["IV"])
    key = key[1:len(key)-1]
    iv = iv[1:len(iv)-1]

    // get previous records
    orgciphertext, _ := APIstub.GetState(args[1])
    var orgarray []interface{}
    if len(orgciphertext) != 0 {
        bytearray, err := sw.AESCBCPKCS7Decrypt(key, orgciphertext)
        if err != nil {
            panic(err)
        }
        if err = json.Unmarshal(bytearray, &orgarray); err != nil {
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
    orgarrayAsBytes, _ := json.Marshal(orgarray)
    ciphertext, err := sw.AESCBCPKCS7EncryptWithIV(iv, key, orgarrayAsBytes)
    if err != nil {
        panic(err)
    }

    APIstub.PutState(args[1], ciphertext)

    return shim.Success(nil)
}

func (s *SmartContract) decRecord(APIstub shim.ChaincodeStubInterface, args[]string) sc.Response {
    ciphertext, _ := APIstub.GetState(args[1])
    if ciphertext == nil {
        return shim.Success(nil)
    }

    // get decrypt key and iv
    decryptKV, err := APIstub.GetTransient()
    if err != nil {
        panic(err)
    }
    key, _ := json.Marshal(decryptKV["DECKEY"])
    key = key[1:len(key)-1]

    // decrpyt ciphertext
    plaintext, err := sw.AESCBCPKCS7Decrypt(key, ciphertext)
    if err != nil {
        panic(err)
    }

    // get record according to year
    var plainarray []interface{}
    if err = json.Unmarshal(plaintext, &plainarray); err != nil {
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

func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
    return shim.Success(nil)
}

// The main function is only relevant in unit test mode. Only included here for completeness.
func main() {

    writemap = make(map[string][]interface{})
    // Create a new Smart Contract
    err := shim.Start(new(SmartContract))
    if err != nil {
        fmt.Printf("Error creating new Smart Contract: %s", err)
    }
}
