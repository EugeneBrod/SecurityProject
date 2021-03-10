package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	"strconv"
	_ "strconv"
	_ "strings"
	"testing"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	// getting user that doesn't exist
	alice, err := GetUser("alice", "fubar")
	if err == nil {
		t.Error("no users exist yet, error: ")
		return
	}

	// initializing alice
	alice, err = InitUser("alice", "fubar")
	if err != nil {
		t.Error("failed to initialize alice, error: ", err)
		return
	}

	// try to initialize new account for alice, should fail
	alice2, err := InitUser("alice", "fubar")
	if err == nil {
		t.Error("allowed another account with username alice, error :")
		return
	}

	// get another instance of alice
	alice2, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("failed to get another instance of alice, error: ", err)
		return
	}

	// make sure both instances of alice the same
	if !reflect.DeepEqual(alice, alice2) {
		t.Error("two instances of alice are not the same, error: ", err)
		return
	}

	// reject 3rd instance of alice because of wrong password
	alice3, err := GetUser("alice", "fubor")
	_ = alice3
	if err == nil {
		t.Error("failed to recognize wrong password")
	}

	blank, err := InitUser("", "")
	if err != nil {
		t.Error(err)
		return
	}
	blank.StoreFile("", []byte(""))
	_, err = blank.LoadFile("")
	if err == nil {
		t.Error("file should not exist")
		return
	}


}

func TestStorage(t *testing.T) {
	clear()
	t.Log("testing storage, appends, and overwrites")

	alice, err := InitUser("alice", "fubar")
	alice2, err := GetUser("alice", "fubar")


	v := []byte("This is a test")

	// alice stores file, alice2 retrieves it, should be equal
	alice.StoreFile("file1", v)
	v2, err := alice2.LoadFile("file1")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("file mutated when loaded")
		return
	}

	// alice appends to stored file, alice2 loads it
	append := []byte("this is an append")
	err = alice2.AppendFile("file1", append)
	if err != nil {
		t.Error("Failed to append to file1", err)
		return
	}

	if err != nil {
		t.Error("Failed to load appended file", err)
		return
	}

	v2, err = alice2.LoadFile("file1")

	if !reflect.DeepEqual(string(v2), string(v) + string(append)) {
		t.Error("Append not correct")
		return
	}

	wx := []byte("this is an overwrite")
	alice.StoreFile("file1", wx)

	w, err := alice.LoadFile("file1")
	w2, err := alice2.LoadFile("file1")
	if err != nil {
		t.Error("Failed to Load an overwritten file", err)
		return
	}

	// User A overwrites file1, User B loads file1, should match
	if !(reflect.DeepEqual(w, w2) && reflect.DeepEqual(w, wx)) {
		t.Error("loaded file does not match most recent overwrite")
		return
	}

	append = []byte("append to the overwrite")
	err = alice.AppendFile("file1", append)
	if err != nil {
		t.Error("failed to load appended overwritten file, error: ", err)
		return
	}
	w, err = alice2.LoadFile("file1")
	if err != nil {
		t.Error("failed to load appended overwritten file, error: ", err)
		return
	}
	if !reflect.DeepEqual(string(w), string(wx) + string(append)) {
		t.Error("loaded appended file does not match appended data")
		return
	}

	err = alice.AppendFile("file1", append)
	err = alice.AppendFile("file1", append)
	w, err = alice2.LoadFile("file1")
	if err != nil {
		t.Error("failed to load appended overwritten file, error: ", err)
		return
	}

	if !reflect.DeepEqual(string(w), string(wx)+string(append)+string(append)+string(append)) {
		t.Error("loaded appended file does not match appended data")
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := alice.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}

	bits := []byte("append on non existant file")
	err = alice.AppendFile("file1", bits)
	if err == nil {
		t.Error("Failed to throw error when appending to non-existant file")
		return
	}

	//cloud := userlib.DatastoreGetMap()
	//userlib.DebugMsg("%s", cloud)

	alice.StoreFile("file1", bits)
}


func TestShare(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	alice.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	magic_string, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = bob.ReceiveFile("file1", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = bob.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	// at this point alice stored a file, shared it with bob, bob was able to load it
	charlie, err := InitUser("charlie", "pass")

	// bob shares with charlie
	magic_string, err = bob.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	// charlie recieves file from invalid user
	err = charlie.ReceiveFile("file1", "pep", magic_string)
	if err == nil {
		t.Error("Failed to recognize wrong signature")
		return
	}

	err = charlie.ReceiveFile("file1", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = charlie.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	//make sure bob cant revoke alices access

	err = bob.RevokeFile("file1", "alice")
	if err == nil {
		t.Error("bob was able to revoke alice's access")
		return
	}
	err = bob.RevokeFile("file1", "charlie")
	if err == nil {
		t.Error("only owner of file calls revoke")
		return
	}

	_, err = charlie.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	// revoke bob's access, charlie should not be able to access file

	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("failed to revoke file from bob, error: ", err)
		return
	}

	err = bob.AppendFile("file1", []byte("hey there"))
	if err == nil {
		t.Error("appended to nonexistent file")
		return

	}
	v3, err := bob.LoadFile("file1")
	if err == nil {
		t.Error("failed to revoke bobs access to file, his file: ", string(v3))
		return
	}

	_, err = charlie.LoadFile("file1")
	if err == nil {
		t.Error("charlie did not lose access to file when should have")
		return
	}


	clear()
	jake, err := InitUser("jake", "foo")
	tom, err := InitUser("tom", "bar")

	file := []byte("this is a big test")

	jake.StoreFile("file1", file)
	str, err := jake.ShareFile("file1", "jake")
	if err == nil {
		t.Error("non tree structure")
	}
	err = jake.ReceiveFile("file1", "jake", str)
	if err == nil {
		t.Error("invalid token")
	}
	str, err = jake.ShareFile("file1", "tom")
	if err != nil {
		t.Error(err)
	}
	err = tom.ReceiveFile("file1", "jake", str)
	if err != nil {
		t.Error(err)
	}
	err = jake.RevokeFile("file1", "tom")
	if err != nil {
		t.Error(err)
	}


	clear()
	alice, err = InitUser("alice", "fubar")
	alice.StoreFile("file1", []byte("this is a test"))

	i := 0
	users := make(map[int]*User)
	for i < 5 {
		users[i], err = InitUser(strconv.Itoa(i), strconv.Itoa(i))
		if err != nil {
			t.Error(err)
			return
		}
		str, err := alice.ShareFile("file1", strconv.Itoa(i))
		if err != nil {
			t.Error(err)
			return
		}
		err = users[i].ReceiveFile("file1", "alice", str)
		if err != nil {
			t.Error(err)
			return
		}
		i++
	}

	i = 0
	for i < 5 {
		file, err := users[i].LoadFile("file1")
		if err != nil {
			t.Error(err)
			return
		}
		if string(file) != "this is a test" {
			t.Error("files dont match")
			return
		}
		i++
	}

	clear()

	aalice, err := InitUser("aalice", "foo")
	if err != nil {
		t.Error(err)
		return
	}
	bben, err := InitUser("bben", "foo")
	if err != nil {
		t.Error(err)
		return
	}
	ccolin, err := InitUser("ccolin", "foo")
	if err != nil {
		t.Error(err)
		return
	}

	dan, err := InitUser("dan", "foo")
	if err != nil {
		t.Error(err)
		return
	}

	aalice.StoreFile("file1", []byte("cat"))
	bbentoken, err := aalice.ShareFile("file1", "bben")
	if err != nil {
		t.Error(err)
		return
	}
	err = bben.ReceiveFile("file1", "aalice", bbentoken)
	if err != nil {
		t.Error(err)
		return
	}

	ccolintoken, err := aalice.ShareFile("file1", "ccolin")
	if err != nil {
		t.Error(err)
		return
	}
	err = ccolin.ReceiveFile("file1", "aalice", ccolintoken)
	if err != nil {
		t.Error(err)
		return
	}

	str, err = bben.ShareFile("file1", "dan")
	if err != nil {
		t.Error(err)
		return
	}

	err = dan.ReceiveFile("file1", "bben", str)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = dan.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}


	_, err = ccolin.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	err = aalice.RevokeFile("file1", "bben")
	if err != nil {
		t.Error(err)
		return
	}

	_, err = dan.LoadFile("file1")
	if err == nil {
		t.Error("dan shouldnt be able to get file (child of revoked user")
		return
	}

	_, err = ccolin.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	err = aalice.AppendFile("file1", []byte("appendage"))
	if err != nil {
		t.Error(err)
		return
	}

	_, err = bben.LoadFile("file1")
	if err == nil {
		t.Error("failed to revoke bben access")
		return
	}

	err = bben.AppendFile("file1", []byte("bbenappend"))
	if err == nil {
		t.Error("allowed bben access to append after revoke")
		return
	}

	str, err = aalice.ShareFile("file1", "bben")
	if err != nil {
		t.Error(err)
		return
	}
	err = bben.ReceiveFile("file2", "aalice", str)
	if err != nil {
		t.Error(err)
		return
	}

	bben.StoreFile("file2", []byte("bbens overwrite"))
	overwrite, err := bben.LoadFile("file2")
	if !reflect.DeepEqual(overwrite, []byte("bbens overwrite")) {
		t.Error("loaded file not same")
		return
	}



}
