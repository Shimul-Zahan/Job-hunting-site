import React, { useContext, useEffect, useRef, useState } from 'react'
import axios from 'axios'
import Message from './Message';
import { io } from 'socket.io-client'
import { AuthContext } from '../providers/AuthProviders';

const Chat = () => {

    const [allUsersFromDb, setAllUsersFromDb] = useState([]);
    const [reciever, setReciever] = useState([])
    const [onlineUsers, setOnlineUsers] = useState([])
    // const userForChatApp = localStorage.getItem('userForChatApp');
    // const user = JSON.parse(userForChatApp);
    const { user } = useContext(AuthContext);
    const socket = useRef()
    console.log(user, 'login user here');


    useEffect(() => {
        const url = "http://localhost:5000/users";
        fetch(url)
            .then((res) => res.json())
            .then((data) => {
                console.log(data);
                setAllUsersFromDb(data);
                console.log(data);
            })
            .catch((error) => {
                console.log(error);
            });
    }, []);


    useEffect(() => {
        socket.current = io('ws://localhost:8000');
    }, [])

    // socket e data pathabo
    useEffect(() => {
        socket.current.emit('addActiveUser', user._id);
    }, [])

    // get active user
    useEffect(() => {
        socket.current.on('getActiveUser', (activeUsers) => {
            setOnlineUsers(activeUsers);
        });
    }, [])


    const allUsers = allUsersFromDb?.filter(u => u._id !== user._id)
    console.log(allUsers);

    return (
        <div className='max-h-[85vh] mb-20'>
            <div className='h-[85vh]'>
                <div className="grid grid-cols-1 gap-2 lg:grid-cols-5 lg:gap-1">
                    <div className="rounded-lg  p-2">
                        <li className='p-2 mb-10 my-2 text-xl font-medium flex justify-start items-center gap-2 border border-black rounded-lg'>
                            <img src={user?.photoURL} alt="" className='w-12 h-12 rounded-full' />
                            <div className='text-white'>
                                <h1 className='text-base font-bold capitalize text-black'>{user?.name}</h1>
                                <p className='text-xs text-black'>My Self</p>
                            </div>
                        </li>
                        <div className='overflow-y-scroll h-[60vh]'>
                            {
                                allUsers && allUsers.map((chat, idx) =>
                                    <li onClick={() => setReciever(chat)} key={idx} className='p-2 relative my-2 cursor-pointer hover:shadow-lg text-xl font-medium flex justify-start items-center gap-2 border border-black rounded-lg'>
                                        <img src={chat?.photoURL ? chat?.photoURL : "https://icon-library.com/images/anonymous-avatar-icon/anonymous-avatar-icon-25.jpg"} alt="" className='w-12 h-12 rounded-full' />
                                        <div>
                                            <h1 className='text-base font-bold capitalize'>{chat?.name}</h1>
                                            {onlineUsers.some(user => user.userId === chat._id) ? (
                                                <div className="flex items-center">
                                                    <span className="absolute bottom-4 left-12 w-2 h-2 rounded-full bg-green-700 mr-2"></span>
                                                    <p className="text-sm text-green-700">Online</p>
                                                </div>
                                            ) : (
                                                <div className="flex items-center">
                                                    <span className="absolute bottom-4 left-12 w-2 h-2 rounded-full bg-red-500 mr-2"></span>
                                                    <p className="text-sm text-red-500">Offline</p>
                                                </div>
                                            )}
                                        </div>
                                    </li>
                                )
                            }
                        </div>
                    </div>
                    <div className="rounded-lg lg:col-span-4">
                        <Message socket={socket} reciever={reciever} currentUser={user} onlineUsers={onlineUsers} />
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Chat