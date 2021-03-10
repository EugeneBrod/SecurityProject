package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

func iv() []byte {
	return userlib.RandomBytes(userlib.AESBlockSize)
}

func StringToUUID(name string) uuid.UUID {
	temp := userlib.Hash([]byte (name))
	return bytesToUUID(temp[:16])
}

func AddHMAC(HMACKey []byte, data []byte) (result []byte, err error) {
	if len(HMACKey) < 16 {return nil, errors.New("corrupt key")}
	sig, err := userlib.HMACEval(HMACKey[:16], data)
	if err != nil {return nil, err}
	result = append(data, sig...)
	return result, err
}

func CheckHMAC(HMACKey []byte, data []byte) (content []byte, err error) {
	if len(HMACKey) < 16 {return nil, errors.New("corrupt key")}
	if len(data) < 65 {
		return nil, errors.New("could not establish integrity")
	}
	code := data[len(data)-64:]
	content = data[:len(data)-64]
	newCode, err := userlib.HMACEval(HMACKey[:16], content)
	if err != nil {return nil, err}
	if !userlib.HMACEqual(code, newCode) {
		return nil, errors.New("could not establish integrity")
	}
	return content, err
}
func signData(data []byte, signKey userlib.DSSignKey) ([]byte, error) {
	signature, err := userlib.DSSign(signKey, data)
	if err != nil {return nil, err}
	return append(data, signature...), err
}
func HashAndSalt(password string, salt []byte) []byte {
	passSalt := append([]byte(password), salt...)
	passSaltHash := userlib.Hash(passSalt)
	return passSaltHash[:]
}

func CheckSig(data []byte, verifyKey userlib.DSVerifyKey) ([]byte, error) {

	if len(data) < 256 {
		return nil, errors.New("no signature on file")
	}
	signature := data[len(data)-256:]
	content := data[:len(data)-256]
	err := userlib.DSVerify(verifyKey, content, signature)
	return content, err
}

func CompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
func pad(buf []byte) ([]byte) {
	bufLen:= len(buf)
	padLen:= userlib.AESBlockSize - (bufLen % userlib.AESBlockSize)
	for i:=0; i < padLen; i++ {
		buf = append(buf, byte(padLen))
	}
	return buf
}

func unpad(buf []byte) ([]byte, error) {
	bufLen := len(buf)
	if bufLen == 0 {
		return nil, errors.New("cryptgo/padding: invalid padding size")
	}

	pad := buf[bufLen-1]
	padLen := int(pad)
	if padLen > bufLen || padLen > userlib.AESBlockSize {
		return nil, errors.New("cryptgo/padding: invalid padding size")
	}

	for _, v := range buf[bufLen-padLen : bufLen-1] {
		if v != pad {
			return nil, errors.New("cryptgo/padding: invalid padding")
		}
	}

	return buf[:bufLen-padLen], nil
}

// TODO

/* type Room

	fields
		datahash
		uuid
		Key

	functions
		make room
		change key and relocate files
		load data
		check integrity of data
		upload data
*/
type Room struct {
	Hash [64]byte
	UUID uuid.UUID
	Key []byte
}

func (room *Room) MakeRoom(data []byte) (err error) {
	room.UUID = bytesToUUID(userlib.RandomBytes(32))
	room.Key = userlib.RandomBytes(32)
	room.Hash = userlib.Hash(data)
	room.Upload(data)
	return err
}

func (room *Room) Upload(data []byte) {
	data = pad(data)
	data = userlib.SymEnc(room.Key, iv(), data)
	userlib.DatastoreSet(room.UUID, data)
}

func (room *Room) Load() (data []byte, err error) {
	data, ok := userlib.DatastoreGet(room.UUID)
	if !ok {return nil, errors.New("room data does not exist")}
	data = userlib.SymDec(room.Key, data)
	data, err = unpad(data)
	if err != nil {return nil, err}
	err = room.Check(data)
	if err != nil {return nil, err}
	return data, err
}

func (room *Room) Secure() (err error) {
	data, err := room.Load()
	if err != nil {return err}

	err = room.MakeRoom(data)
	return err
}

func (room *Room) Check(data []byte) (err error) {
	hash := userlib.Hash(data)
	if !CompareBytes(hash[:], room.Hash[:]) {
		return errors.New("could not establish room integrity")
	}
	return err
}


/*
type House

	fields
		rooms
		roomHashes
		signaturekey

	functions
		make house
		change keys and relocate files
		load file
		check integrity of all rooms
		add room
*/
type House  struct {
	Rooms []Room
}

func (house *House) MakeHouse(data []byte, uuid uuid.UUID, key []byte, HMACKey []byte, signKey userlib.DSSignKey) (err error) {
	var room Room
	err = room.MakeRoom(data)
	if err != nil {return err}
	house.Rooms = append(house.Rooms, room)
	err = house.Upload(uuid, key, HMACKey, signKey)
	return err
}

func (house *House) Upload(uuid uuid.UUID, key []byte, HMACKey []byte, signKey userlib.DSSignKey) (err error) {
	mHouse, err := json.Marshal(house)
	if err != nil {return err}
	mHouse = pad(mHouse)
	mHouse = userlib.SymEnc(key, iv(), mHouse)
	mHouse, err = AddHMAC(HMACKey, mHouse)
	if err != nil {return err}
	mHouse, err = signData(mHouse, signKey)
	if err != nil {return err}
	userlib.DatastoreSet(uuid, mHouse)
	return err
}

func (house *House) Secure() (err error) {
	for _, room := range house.Rooms {
		err = room.Secure()
		if err != nil {return err}
	}
	return err
}

func (house *House) Load() (data []byte, err error) {
	for _, room := range house.Rooms {
		temp, err := room.Load()
		if err != nil {return nil, err}
		data = append(data, temp...)
	}
	return data, err
}

func (house *House) Check() (err error) {
	for _, room := range house.Rooms {
		_, err = room.Load()
		if err != nil {return err}
	}
	return err
}

func (house *House) AddRoom(data []byte) (err error) {
	var room Room
	err = room.MakeRoom(data)
	if err != nil {return err}
	house.Rooms = append(house.Rooms, room)
	return err
}

func (house *House) Hash() (hash [64]byte, err error) {
	mhouse, err := json.Marshal(house)
	hash = userlib.Hash(mhouse)
	return hash, err
}
/*
------------------------------------------------
type LockBox
	fields
		HouseKey
		BranchKeys


type Node
	fields
		Owner
		branches
		branches hashes
		lockbox
		lockboxString

	functions
		load lockbox
*/
type LockBox struct {
	HouseKey []byte
	HouseSignKey userlib.DSSignKey
	HouseHMACKey []byte
	BranchKeys map[string][]byte
	BranchHMACKeys map[string][]byte
}

func (safe *LockBox) Make(houseKey []byte, signKey userlib.DSSignKey, HMACKey []byte) {
	safe.HouseKey = houseKey
	safe.HouseSignKey = signKey
	safe.HouseHMACKey = HMACKey
	safe.BranchKeys = make(map[string][]byte)
	safe.BranchHMACKeys = make(map[string][]byte)
}

type Node struct {
	Owner string
	Branches map[string]Node
	BranchHashes map[string][]byte
	safe *LockBox
	SafeString []byte
}

func (node *Node) Make(owner string, safeKey []byte, houseKey []byte, HMACKey []byte, housesig userlib.DSSignKey, houseHMACKey []byte) (err error) {
	node.Owner = owner
	var safe LockBox
	safe.Make(houseKey, housesig, houseHMACKey)
	mSafe, err := json.Marshal(safe)
	if err != nil {return err}
	mSafe = pad(mSafe)
	mSafe = userlib.SymEnc(safeKey, iv(), mSafe)
	node.SafeString = mSafe
	node.Branches = make(map[string]Node)
	node.BranchHashes = make(map[string][]byte)
	return err
}

func (node *Node) LoadSafe(key []byte) (err error) {
	if len(key) == 0 {
		return errors.New("key corrupted")
	}
	mSafe := userlib.SymDec(key, node.SafeString)
	mSafe, err = unpad(mSafe)
	if err != nil {return err}
	var safe LockBox
	err = json.Unmarshal(mSafe, &safe)
	if err != nil {return err}
	node.safe = &safe
	return err
}

func (node *Node) ReturnHash() ([]byte, error) {
	data, err := json.Marshal(node)
	if err != nil {return nil, err}
	hash := userlib.Hash(data)
	return hash[:], err
}

func (node *Node) Find(user string) (*Node) {

	if node.Owner == user {
		return node
	}
	for _, temp := range node.Branches {
		temp2 := temp.Find(user)
		if temp2 != nil {
			return temp2
		}
	}
	return nil
}


func (node *Node) RemoveChild(user string) {
	if _, ok := node.Branches[user]; ok {
		delete(node.Branches, user)
		return
	}
	for _, temp := range node.Branches {
		temp.RemoveChild(user)
	}
}

func (node *Node) MarshalSafe(safeKey []byte) (err error) {
	mSafe, err := json.Marshal(node.safe)
	if err != nil {return err}
	mSafe = pad(mSafe)
	mSafe = userlib.SymEnc(safeKey, iv(), mSafe)
	node.SafeString = mSafe
	return err
}


/*


type LockTree

	fields
		root
		rootHash


	functions
		make tree
		find node
		return owner
		change house locks
		revoke user

*/
type LockTree struct {
	Root Node
	RootHash []byte
}

func (tree *LockTree) Make(owner string, safeKey []byte, houseKey []byte, safeHMACKey []byte, housesig userlib.DSSignKey, houseHMACKey []byte) (err error) {
	var node Node
	err = node.Make(owner, safeKey, houseKey, safeHMACKey, housesig, houseHMACKey)
	if err != nil {return err}
	tree.Root = node
	tree.RootHash, err = node.ReturnHash()
	return err
}

func (tree *LockTree) Find(owner string) (node *Node, err error) {
	node = &tree.Root
	result := node.Find(owner)
	if result == nil {return result, errors.New("could not find node")}
	return result, nil
}

func (tree *LockTree) AddNode(pBoxKey []byte, pBoxHMAC []byte, parent string, child string, cBoxKey []byte, cBoxHMAC []byte) (err error) {
	// add child to userdata's node on locktree
	// 1. create child node and lockbox
	// 2. marshal lockbox into safestring
	// 3. find userdata's node
	// 4. add node to userdata's branches
	// 5. unmarshal userdata's lockbox
	// 6. add child node keys to lockbox
	// 7. marshal userdata's lockbox into safestring
	parentnode, err := tree.Find(parent)
	if parentnode == nil {
		return errors.New("could not find parent node in tree")
	}
	err = parentnode.LoadSafe(pBoxKey)
	var childnode Node
	err = childnode.Make(child, cBoxKey, parentnode.safe.HouseKey, cBoxHMAC, parentnode.safe.HouseSignKey, parentnode.safe.HouseHMACKey)
	parentnode.Branches[child] = childnode
	parentnode.safe.BranchKeys[child] = cBoxKey
	parentnode.safe.BranchHMACKeys[child] = cBoxHMAC
	err = parentnode.MarshalSafe(pBoxKey)
	return err
}

func ChangeHouseKey(houseKey []byte, node Node, safeKey []byte, safeHMACKey []byte) (err error) {
	err = node.LoadSafe(safeKey)
	if err != nil {return err}
	node.safe.HouseKey = houseKey
	for user, child := range node.Branches {
		err = ChangeHouseKey(houseKey, child, node.safe.BranchKeys[user], node.safe.BranchHMACKeys[user])
		if err != nil {return err}
	}
	err = node.MarshalSafe(safeKey)
	return err
}

func (tree *LockTree) RemoveAndChangeHouseKey(safeKey []byte, safeHMACKey []byte, user string) (err error) {
	tree.Root.RemoveChild(user)
	newKey := userlib.RandomBytes(32)
	parent := tree.Root
	err = ChangeHouseKey(newKey, parent, safeKey, safeHMACKey)

	return err
}
/*
------------------------------------------
type metafile

	fields
		house
		houseUUID
		houseHash
		houseSignatureKey

		locktree
		locktreeUUID
		locktreeHash


	functions
		create house
		load house
		change house key and location
		check house integrity
		update house hash
		upload house

		create locktree
		load locktree
		change locktree key and location
		check locktree integrity
		update lock hash
		upload locktree

		update hashes
*/
type MetaFile struct {
	house House
	HouseUUID uuid.UUID
	HouseHash [64]byte
	HouseVerifyKey userlib.DSVerifyKey
	Locktree LockTree
	LockTreeHash [64]byte


}

func (metafile *MetaFile) Make(data []byte, owner string, houseKey []byte, houseHMACKey []byte,
	houseSignKey userlib.DSSignKey, safeKey []byte, safeHMACKey []byte, HouseVer userlib.DSVerifyKey, ) (err error) {

	metafile.HouseUUID = bytesToUUID(userlib.RandomBytes(32))
	metafile.HouseVerifyKey = HouseVer
	err = metafile.house.MakeHouse(data, metafile.HouseUUID, houseKey, houseHMACKey, houseSignKey)
	if err != nil {return err}
	metafile.HouseHash, err = metafile.house.Hash()
	if err != nil {return err}
	err = metafile.Locktree.Make(owner, safeKey, houseKey, safeHMACKey, houseSignKey, houseHMACKey)
	if err != nil {return err}
	err = metafile.LocktreeHashandMarshal()
	if err != nil {return err}
	return err
}

func (metafile *MetaFile) LocktreeHashandMarshal() (err error) {
	data, err := json.Marshal(metafile.Locktree)
	if err != nil {return err}
	metafile.LockTreeHash = userlib.Hash(data)
	return err
}

func (metafile *MetaFile) LoadHouse(user string, safeKey []byte, safeHMACKey []byte) (err error) {
	node, err := metafile.Locktree.Find(user)
	if err!=nil {return errors.New("could not find user in share tree")}
	err = node.LoadSafe(safeKey)
	if err != nil {return err}
	mHouse, ok := userlib.DatastoreGet(metafile.HouseUUID)
	if !ok {return errors.New("could not retrieve house from cloud")}
	mHouse, err = CheckSig(mHouse, metafile.HouseVerifyKey)
	if err != nil {return err}
	mHouse, err = CheckHMAC(node.safe.HouseHMACKey, mHouse)
	if err != nil {return err}
	mHouse = userlib.SymDec(node.safe.HouseKey, mHouse)
	mHouse, err = unpad(mHouse)
	if err != nil {return err}
	var house House
	err = json.Unmarshal(mHouse, &house)
	if err != nil {return err}
	metafile.house = house
	return err
}


type File struct {
	Filename string
	metafile MetaFile
	MetafileUUID uuid.UUID
	MetafileKey []byte
	MetafileHMAC []byte
	MetafileSig userlib.DSSignKey
	MetafileVer userlib.DSVerifyKey
	LockboxKey []byte
	LockboxHMACKey []byte
}

func (file *File) Overwrite(owner string, data []byte, user string, lockboxkey []byte, lockboxHMAC []byte) (err error) {
	err = file.LoadMetaFile(owner, file.MetafileUUID, file.MetafileVer, file.MetafileHMAC, file.MetafileKey)
	if err != nil {return err}
	file.metafile.house.Rooms = nil
	err = file.metafile.house.AddRoom(data)
	if err != nil {return err}

	return err
}

func (file *File) LoadMetaFile(owner string, uuid uuid.UUID, verifykey userlib.DSVerifyKey, hmacKey []byte, enckey []byte) (err error) {
	mMetafile, ok := userlib.DatastoreGet(file.MetafileUUID)
	if !ok {return errors.New("could not retrieve metafile from cloud")}
	mMetafile, err = CheckSig(mMetafile, file.MetafileVer)
	if err != nil {return err}
	mMetafile, err = CheckHMAC(file.MetafileHMAC, mMetafile)
	if err != nil {return err}
	mMetafile = userlib.SymDec(file.MetafileKey, mMetafile)
	mMetafile, err = unpad(mMetafile)
	if err != nil {return err}
	var metafile MetaFile
	err = json.Unmarshal(mMetafile, &metafile)
	if err != nil {return err}
	file.metafile = metafile
	err = file.metafile.LoadHouse(owner, file.LockboxKey, file.LockboxHMACKey)
	if err != nil {return err}
	mLocktree, err := json.Marshal(file.metafile.Locktree)
	hash := userlib.Hash(mLocktree)
	if !CompareBytes(hash[:], file.metafile.LockTreeHash[:]) {
		return errors.New("Locktree compromised")
	}
	return err
}

func (file *File) MarshalMetafile(owner string, lockboxkey []byte) (err error) {
	node, err := file.metafile.Locktree.Find(owner)
	err = node.LoadSafe(lockboxkey)
	err = file.metafile.house.Upload(file.metafile.HouseUUID, node.safe.HouseKey, node.safe.HouseHMACKey, node.safe.HouseSignKey)
	if err != nil {return err}
	err = file.metafile.LocktreeHashandMarshal()
	mMetafile, err := json.Marshal(file.metafile)
	if err != nil {return err}
	mMetafile = pad(mMetafile)
	mMetafile = userlib.SymEnc(file.MetafileKey, iv(), mMetafile)
	mMetafile, err = AddHMAC(file.MetafileHMAC, mMetafile)
	if err != nil {return err}
	mMetafile, err = signData(mMetafile, file.MetafileSig)
	if err != nil {return err}
	userlib.DatastoreSet(file.MetafileUUID, mMetafile)
	return err
}

/*
type User
	fields
		Username
		Password
		MyFiles
		PrivateRSAKey
		PrivateDSKey

	functions
		update cloud
*/
type User struct {
	Username string
	Password []byte
	Salt []byte
	MyFiles map[string]File
	PrivateRSAKey userlib.PKEDecKey
	PrivateDSKey userlib.DSSignKey
}

func (user *User) UpdateCloud() (err error) {
	key := userlib.Argon2Key(user.Password, user.Salt, 32)
	encKey, err := userlib.HashKDF(key, []byte("enc"))
	if err != nil {return err}
	HMACKey, err := userlib.HashKDF(key, []byte("hmac"))
	if err != nil {return err}
	mUser, err := json.Marshal(user)
	if err != nil {return err}
	mUser = pad(mUser)
	mUser = userlib.SymEnc(encKey[:32], iv(), mUser)
	mUser, err = AddHMAC(HMACKey, mUser)
	if err != nil {return err}
	mUser, err = signData(mUser, user.PrivateDSKey)
	if err != nil {return err}
	userlib.DatastoreSet(StringToUUID(user.Username), mUser)
	return err
}

func (user *User) LoadUser(username string, password []byte, salt []byte,) (err error){
	mUser, ok := userlib.DatastoreGet(StringToUUID(username))
	if !ok {return errors.New("could not find struct for given username")}
	verifykey, ok := userlib.KeystoreGet(username + "DS")
	if !ok {return errors.New("could not find signature verification key")}
	mUser, err = CheckSig(mUser, verifykey)
	if err != nil {return err}
	key := userlib.Argon2Key(password, salt, 32)
	encKey, err := userlib.HashKDF(key, []byte("enc"))
	if err != nil {return err}
	HMACKey, err := userlib.HashKDF(key, []byte("hmac"))
	if err != nil {return err}
	mUser, err = CheckHMAC(HMACKey, mUser)
	if err != nil {return err}
	mUser = userlib.SymDec(encKey[:32], mUser)
	mUser, err = unpad(mUser)
	if err != nil {return err}
	err = json.Unmarshal(mUser, user)
	return err
}

/*
type PasswordTable
	fields
		Table
		Salt

	functions
		create table
		add entry
		check password
*/
type PasswordTable struct {
	Table map[string][]byte
	Salt map[string][]byte
}

func (table *PasswordTable) Make() {
	table.Table = make(map[string][]byte)
	table.Salt = make(map[string][]byte)
}

func (table *PasswordTable) AddUser(name string, password string) (salt []byte, err error) {
	table.Salt[name] = userlib.RandomBytes(32)
	table.Table[name] = HashAndSalt(password, table.Salt[name])
	return table.Salt[name], err
}

func (table *PasswordTable) Check(name string, password string, salt []byte) bool {
	if !CompareBytes(table.Table[name], HashAndSalt(password, salt)) {
		return false
	}
	return true
}

/*
type AccessToken
	fields
		SafeBytes
		Safe
		Key

	functions
		access safe
		make token

type Safe
	fields
		MetafileUUID
		MetafileKey
		LockBoxKey
 */
type AccessToken struct {
	SafeBytes []byte
	safe Safe
	RSAKey []byte
	HMACKey []byte
}

type Safe struct {
	MetafileUUID uuid.UUID
	MetafileKey []byte
	MetafileHMACKey []byte
	MetafileSig userlib.DSSignKey
	MetafileVer userlib.DSVerifyKey
	LockboxKey []byte
	LockboxHMACkey []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// check if pass table exists
	var table PasswordTable
	mTable, ok := userlib.DatastoreGet(StringToUUID("passwordtable"))
	if !ok {
		table.Make()
		mTable, err = json.Marshal(table)
		userlib.DatastoreSet(StringToUUID("passwordtable"), mTable)
	}

	mTable, ok = userlib.DatastoreGet(StringToUUID("passwordtable"))
	err = json.Unmarshal(mTable, &table)
	if err != nil {return nil, err}

	// check if user already exists
	if _, ok := table.Table[username]; ok {
		return nil, errors.New("username taken")
	}
	userdata.Salt, err = table.AddUser(username, password)
	if err != nil {return nil, err}

	userdata.Username = username
	userdata.Password = []byte(password)

	sign, ver, err := userlib.DSKeyGen()
	if err != nil {return nil, err}
	userdata.PrivateDSKey = sign
	err = userlib.KeystoreSet(username + "DS", ver)
	if err != nil {return nil, err}

	pk, sk, err := userlib.PKEKeyGen()
	if err != nil {return nil, err}
	userdata.PrivateRSAKey = sk
	err = userlib.KeystoreSet(username + "RSA", pk)
	if err != nil {return nil, err}

	userdata.MyFiles = make(map[string]File)

	mTable, err = json.Marshal(table)
	if err != nil {return nil, err}
	userlib.DatastoreSet(StringToUUID("passwordtable"), mTable)
	err = userdata.UpdateCloud()
	if err != nil {return nil, err}
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	// check if any users exist
	mTable, ok := userlib.DatastoreGet(StringToUUID("passwordtable"))
	if !ok {
		return nil, errors.New("no users exist")
	}
	// get table
	var table PasswordTable
	mTable, ok = userlib.DatastoreGet(StringToUUID("passwordtable"))
	err = json.Unmarshal(mTable, &table)
	if err != nil {return nil, err}
	if !table.Check(username, password, table.Salt[username]) {
		return nil, errors.New("either user does not exist or wrong password")
	}
	// get user
	err = userdataptr.LoadUser(username, []byte(password), table.Salt[username])
	if err != nil {return nil, err}
	err = userdata.UpdateCloud()
	if err != nil {return nil, err}
	return userdataptr, err
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	err := userdata.UpdateCloud()
	if len(data) == 0 {
		return
	}

	if val, ok := userdata.MyFiles[filename]; ok {
		file := val
		err := file.Overwrite(userdata.Username, data, userdata.Username, file.LockboxKey, file.LockboxHMACKey)
		err = file.MarshalMetafile(userdata.Username, file.LockboxKey)
		err = userdata.UpdateCloud()
		_ = err
		return
	}
	var file File
	file.Filename = filename
	file.MetafileUUID = bytesToUUID(userlib.RandomBytes(32))
	sign, ver, err := userlib.DSKeyGen()
	file.MetafileSig = sign
	file.MetafileVer = ver
	file.MetafileHMAC = userlib.RandomBytes(32)
	file.MetafileKey = userlib.RandomBytes(32)
	file.LockboxHMACKey = userlib.RandomBytes(32)
	file.LockboxKey = userlib.RandomBytes(32)
	var metafile MetaFile
	housesign, housever, err := userlib.DSKeyGen()
	err = metafile.Make(data, userdata.Username, userlib.RandomBytes(32), userlib.RandomBytes(32),
		housesign, file.LockboxKey, file.LockboxHMACKey, housever)
	mMetafile, err := json.Marshal(metafile)
	mMetafile = pad(mMetafile)
	mMetafile = userlib.SymEnc(file.MetafileKey, iv(), mMetafile)
	mMetafile, err = AddHMAC(file.MetafileHMAC, mMetafile)
	mMetafile, err = signData(mMetafile, file.MetafileSig)
	userlib.DatastoreSet(file.MetafileUUID, mMetafile)

	userdata.MyFiles[file.Filename] = file

	err = file.LoadMetaFile(userdata.Username, file.MetafileUUID,file.MetafileVer, file.MetafileHMAC, file.MetafileKey)
	err = file.MarshalMetafile(userdata.Username, file.LockboxKey)
	err = userdata.UpdateCloud()
	_ = err
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// check if file exists
	if _, ok := userdata.MyFiles[filename]; !ok {
		return errors.New("file does not exist")
	}

	file := userdata.MyFiles[filename]
	err = file.LoadMetaFile(userdata.Username, file.MetafileUUID,file.MetafileVer, file.MetafileHMAC, file.MetafileKey)
	if err != nil {return err}
	err = file.metafile.LoadHouse(userdata.Username, file.LockboxKey, file.LockboxHMACKey)
	if err != nil {return err}
	err = file.metafile.house.AddRoom(data)
	if err != nil {return err}
	node, err := file.metafile.Locktree.Find(userdata.Username)
	if err != nil {return err}
	if node.Owner == "" {return errors.New("could not find user in locktree")}
	err = file.MarshalMetafile(userdata.Username, file.LockboxKey)
	if err != nil {return err}
	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	err = userdata.LoadUser(userdata.Username, userdata.Password, userdata.Salt)
	if err != nil {return nil, err}
	// check if file exists
	if _, ok := userdata.MyFiles[filename]; !ok {
		return nil, errors.New("file does not exist")
	}

	file := userdata.MyFiles[filename]
	err = file.LoadMetaFile(userdata.Username, file.MetafileUUID,file.MetafileVer, file.MetafileHMAC, file.MetafileKey)
	if err != nil {return nil, err}
	err = file.metafile.LoadHouse(userdata.Username, file.LockboxKey, file.LockboxHMACKey)
	if err != nil {return nil, err}
	data, err = file.metafile.house.Load()
	if err != nil {return nil, err}
	err = file.MarshalMetafile(userdata.Username, file.LockboxKey)
	if err != nil {return nil, err}
	err = userdata.UpdateCloud()
	if err != nil {return nil, err}
	return data, err
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	err = userdata.LoadUser(userdata.Username, userdata.Password, userdata.Salt)
	if err != nil {return "", err}
	if _, ok := userdata.MyFiles[filename]; !ok {
		return "", errors.New("file does not exist")
	}

	file := userdata.MyFiles[filename]
	err = file.LoadMetaFile(userdata.Username, file.MetafileUUID,file.MetafileVer, file.MetafileHMAC, file.MetafileKey)
	if err != nil {return "", err}
	tmpnod, err := file.metafile.Locktree.Find(recipient)
	if tmpnod != nil {return "", errors.New("user already has access to file")}
	tmpnod2, err := file.metafile.Locktree.Find(userdata.Username)
	if tmpnod2 == nil {return "", errors.New("you don't have access to file")}

	recLockboxKey := userlib.RandomBytes(32)
	recLockboxHMACKey := userlib.RandomBytes(32)

	var safe Safe
	safe.LockboxKey = recLockboxKey
	safe.LockboxHMACkey = recLockboxHMACKey
	safe.MetafileKey = file.MetafileKey
	safe.MetafileUUID = file.MetafileUUID
	safe.MetafileSig = file.MetafileSig
	safe.MetafileHMACKey = file.MetafileHMAC
	safe.MetafileVer = file.MetafileVer

	var token AccessToken
	safeKey := userlib.RandomBytes(32)
	recRSAkey, ok := userlib.KeystoreGet(recipient + "RSA")
	if !ok {return "", errors.New("recipient does not exist")}
	token.RSAKey, err = userlib.PKEEnc(recRSAkey, safeKey)
	if err != nil {return "", err}

	safeHMACkey := userlib.RandomBytes(32)
	token.HMACKey , err = userlib.PKEEnc(recRSAkey, safeHMACkey)
	if err != nil {return "", err}

	mSafe, err := json.Marshal(safe)

	if err != nil {return "", err}
	mSafe = pad(mSafe)
	mSafe = userlib.SymEnc(safeKey, iv(), mSafe)
	mSafe, err = AddHMAC(safeHMACkey, mSafe)
	if err != nil {return "", err}
	mSafe, err = signData(mSafe, userdata.PrivateDSKey)
	if err != nil {return "", err}
	token.SafeBytes = mSafe

	// add child to userdata's node on locktree
	// 1. create child node and lockbox
	// 2. marshal lockbox into safestring
	// 3. find userdata's node
	// 4. add node to userdata's branches
	// 5. unmarshal userdata's lockbox
	// 6. add child node keys to lockbox
	// 7. marshal userdata's lockbox into safestring

	err = file.metafile.Locktree.AddNode(file.LockboxKey, file.LockboxHMACKey, userdata.Username, recipient, recLockboxKey, recLockboxHMACKey)

	err = file.MarshalMetafile(userdata.Username, file.LockboxKey)
	if err != nil {return "", err}
	err = userdata.UpdateCloud()
	if err != nil {return "", err}
	mtoken, err := json.Marshal(token)
	if err != nil {return "", err}
	return string(mtoken), err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	err := userdata.LoadUser(userdata.Username, userdata.Password, userdata.Salt)
	if err != nil {return err}
	if _, ok := userdata.MyFiles[filename]; ok {
		return errors.New("already have a file with same name")
	}

	mtoken := []byte(magic_string)
	var token AccessToken
	err = json.Unmarshal(mtoken, &token)
	if err != nil {return err}
	verifykey, ok := userlib.KeystoreGet(sender + "DS")
	if !ok {return errors.New("sender does not exist")}
	mSafe, err := CheckSig(token.SafeBytes, verifykey)
	if err != nil {return err}
	safeHMACkey, err := userlib.PKEDec(userdata.PrivateRSAKey, token.HMACKey)
	if err != nil {return err}
	safeENCkey, err := userlib.PKEDec(userdata.PrivateRSAKey, token.RSAKey)
	if err != nil {return err}
	mSafe, err = CheckHMAC(safeHMACkey, mSafe)
	if err != nil {return err}
	mSafe = userlib.SymDec(safeENCkey, mSafe)
	mSafe, err = unpad(mSafe)
	if err != nil {return err}
	var safe Safe
	err = json.Unmarshal(mSafe, &safe)
	if err != nil {return err}

	var file File
	file.Filename = filename
	file.MetafileHMAC = safe.MetafileHMACKey
	file.MetafileSig = safe.MetafileSig
	file.MetafileUUID = safe.MetafileUUID
	file.MetafileKey = safe.MetafileKey
	file.LockboxKey = safe.LockboxKey
	file.LockboxHMACKey = safe.LockboxHMACkey
	file.MetafileVer = safe.MetafileVer

	userdata.MyFiles[filename] = file
	err = userdata.UpdateCloud()
	if err != nil {return err}
	return err
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	err = userdata.LoadUser(userdata.Username, userdata.Password, userdata.Salt)

	if _, ok := userdata.MyFiles[filename]; !ok {
		return errors.New("file does not exist")
	}

	file := userdata.MyFiles[filename]
	err = file.LoadMetaFile(userdata.Username, file.MetafileUUID, file.MetafileVer, file.LockboxHMACKey, file.LockboxKey)
	if err != nil {return err}
	if file.metafile.Locktree.Root.Owner != userdata.Username {
		return errors.New("Not owner of file")
	}
	err = file.metafile.Locktree.RemoveAndChangeHouseKey(file.LockboxKey, file.LockboxHMACKey, target_username)
	if err != nil {return err}

	err = file.MarshalMetafile(userdata.Username, file.LockboxKey)
	return err
}
