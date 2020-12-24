package sshclient

import (
	"fmt"
	"runtime"
	"sync"
)

var mutex sync.Mutex

func GetStack() string {
	trace := make([]byte, 8192)
	count := runtime.Stack(trace, false)
	content := fmt.Sprintf("Dump (%d bytes):\n %s \n", count, trace[:count])
	return content
}

func schedulePrintClientCount() {
	// <-time.After(3 * time.Minute)
	// mutex.Lock()
	// defer mutex.Unlock()
	// fmt.Println("current active", len(clientList))
	// for _, client := range clientList {
	// 	fmt.Println("client", client.stackLog)
	// }
}

func addClientToLog(client *Client) {
	mutex.Lock()
	defer mutex.Unlock()
	clientList = append(clientList, client)
}

func removeClientFromLog(client *Client) {
	mutex.Lock()
	defer mutex.Unlock()
	indexToDelete := -1
	for index, clientInList := range clientList {
		if clientInList == client {
			indexToDelete = index
			break
		}
	}
	if indexToDelete != -1 {
		deleteInClientList(clientList, indexToDelete)
	} else {
		fmt.Println("exit 2 times client", client.stackLog)
	}
}

func deleteInClientList(a []*Client, i int) []*Client {
	a[i] = a[len(a)-1]
	a = a[:len(a)-1]
	return a
}
