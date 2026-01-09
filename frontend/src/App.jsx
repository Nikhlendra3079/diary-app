import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { encryptData, decryptData } from './crypto';
import Calendar from 'react-calendar';
import 'react-calendar/dist/Calendar.css';
import { Moon, Sun, Trash2, Edit2, Search, Lock, Plus } from 'lucide-react';

import API_URL from './config'; 

function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [entries, setEntries] = useState([]);
  const [view, setView] = useState('list'); // list, calendar, editor
  const [darkMode, setDarkMode] = useState(false);
  
  // Auth State
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLogin, setIsLogin] = useState(true);

  // Editor State
  const [currentEntry, setCurrentEntry] = useState(null);
  const [formData, setFormData] = useState({ title: '', content: '', mood: 'Happy', date: new Date().toISOString().split('T')[0] });
  const [search, setSearch] = useState('');

  // Apply Dark Mode
  useEffect(() => {
    if (darkMode) document.documentElement.classList.add('dark');
    else document.documentElement.classList.remove('dark');
  }, [darkMode]);

  // Fetch Entries
  const fetchEntries = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_URL}/entries?search=${search}`, {
        headers: { Authorization: token }
      });
      // Decrypt entries locally before displaying
      const decrypted = res.data.map(e => ({
        ...e,
        content: decryptData(e.Content, password) // Use password stored in memory
      }));
      setEntries(decrypted);
    } catch (err) {
      console.error(err);
      if(err.response?.status === 401) logout();
    }
  };

  useEffect(() => {
    if (user && token) fetchEntries();
  }, [user, token, search]);

  const handleAuth = async (e) => {
    e.preventDefault();
    const endpoint = isLogin ? '/login' : '/signup';
    try {
      const res = await axios.post(`${API_URL}${endpoint}`, { username, password });
      if (isLogin) {
        setToken(res.data.token);
        localStorage.setItem('token', res.data.token);
        setUser({ username });
        // NOTE: In a real app, storing password in state is risky, but necessary for
        // simple client-side decryption without a complex key management system.
      } else {
        alert("Signup successful! Please login.");
        setIsLogin(true);
      }
    } catch (err) {
      alert(err.response?.data?.error || "An error occurred");
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    setEntries([]);
  };

  const handleSave = async () => {
    // Encrypt content before sending
    const encryptedContent = encryptData(formData.content, password);
    const payload = { ...formData, Content: encryptedContent };

    try {
      if (currentEntry) {
        await axios.put(`${API_URL}/entries/${currentEntry.ID}`, payload, { headers: { Authorization: token } });
      } else {
        await axios.post(`${API_URL}/entries`, payload, { headers: { Authorization: token } });
      }
      setView('list');
      setCurrentEntry(null);
      fetchEntries();
    } catch (err) {
      alert("Failed to save");
    }
  };

  const handleDelete = async (id) => {
    if(!confirm("Delete this entry?")) return;
    await axios.delete(`${API_URL}/entries/${id}`, { headers: { Authorization: token } });
    fetchEntries();
  };

  const openEditor = (entry = null) => {
    if (entry) {
      setCurrentEntry(entry);
      setFormData({ 
        title: entry.Title, 
        content: entry.content, // Already decrypted in state
        mood: entry.Mood, 
        date: entry.Date 
      });
    } else {
      setCurrentEntry(null);
      setFormData({ title: '', content: '', mood: 'Happy', date: new Date().toISOString().split('T')[0] });
    }
    setView('editor');
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 transition-colors">
        <div className="bg-white dark:bg-gray-800 p-8 rounded-lg shadow-lg w-96">
          <h1 className="text-2xl font-bold mb-6 text-center text-gray-800 dark:text-white">Secure Diary <Lock className="inline w-5 h-5"/></h1>
          <form onSubmit={handleAuth} className="space-y-4">
            <input className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required />
            <input className="w-full p-2 border rounded dark:bg-gray-700 dark:text-white" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required />
            <button className="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700">{isLogin ? "Login" : "Sign Up"}</button>
          </form>
          <button onClick={() => setIsLogin(!isLogin)} className="w-full text-sm text-blue-500 mt-4 text-center">
            {isLogin ? "Need an account? Sign up" : "Have an account? Login"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 dark:text-white transition-colors">
      {/* Navbar */}
      <nav className="bg-white dark:bg-gray-800 shadow p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold">My Secret Diary</h1>
        <div className="flex gap-4 items-center">
            <button onClick={() => setView('calendar')} className="hover:text-blue-500">Calendar</button>
            <button onClick={() => setView('list')} className="hover:text-blue-500">List</button>
            <button onClick={() => setDarkMode(!darkMode)} className="p-2 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700">
                {darkMode ? <Sun size={20}/> : <Moon size={20}/>}
            </button>
            <button onClick={logout} className="text-red-500">Logout</button>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto p-6">
        {/* Toolbar */}
        {view === 'list' && (
          <div className="flex gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 text-gray-400" size={18} />
              <input 
                className="w-full pl-10 p-2 border rounded dark:bg-gray-800 dark:border-gray-700" 
                placeholder="Search titles..." 
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <button onClick={() => openEditor()} className="bg-blue-600 text-white px-4 py-2 rounded flex items-center gap-2">
              <Plus size={18}/> New Entry
            </button>
          </div>
        )}

        {/* Views */}
        {view === 'editor' && (
          <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
            <h2 className="text-2xl mb-4">{currentEntry ? 'Edit Entry' : 'New Entry'}</h2>
            <input className="w-full mb-4 p-2 border rounded dark:bg-gray-700" placeholder="Title" value={formData.title} onChange={e => setFormData({...formData, title: e.target.value})} />
            <div className="flex gap-4 mb-4">
                <input type="date" className="p-2 border rounded dark:bg-gray-700" value={formData.date} onChange={e => setFormData({...formData, date: e.target.value})} />
                <select className="p-2 border rounded dark:bg-gray-700" value={formData.mood} onChange={e => setFormData({...formData, mood: e.target.value})}>
                    <option>Happy</option>
                    <option>Neutral</option>
                    <option>Sad</option>
                    <option>Excited</option>
                </select>
            </div>
            <textarea className="w-full h-64 p-2 border rounded mb-4 dark:bg-gray-700" placeholder="Write your secret notes here..." value={formData.content} onChange={e => setFormData({...formData, content: e.target.value})} />
            <div className="flex gap-2 justify-end">
                <button onClick={() => setView('list')} className="px-4 py-2 text-gray-500">Cancel</button>
                <button onClick={handleSave} className="bg-blue-600 text-white px-4 py-2 rounded">Save Encrypted</button>
            </div>
          </div>
        )}

        {view === 'calendar' && (
          <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow flex flex-col items-center">
            <Calendar 
                onChange={(date) => {
                    // Filter list by date
                    // For simplicity, we just switch to list view with a date filter or finding the entry
                    alert(`Selected: ${date.toDateString()}`);
                }} 
                tileContent={({ date, view }) => {
                    const dateStr = date.toISOString().split('T')[0];
                    return entries.find(e => e.Date === dateStr) ? <div className="w-2 h-2 bg-blue-500 rounded-full mx-auto mt-1"></div> : null;
                }}
            />
          </div>
        )}

        {view === 'list' && (
            <div className="grid gap-4">
                {entries.map(entry => (
                    <div key={entry.ID} className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow hover:shadow-md transition-shadow">
                        <div className="flex justify-between items-start mb-2">
                            <div>
                                <h3 className="text-xl font-bold">{entry.Title}</h3>
                                <p className="text-sm text-gray-500">{entry.Date} • {entry.Mood}</p>
                            </div>
                            <div className="flex gap-2">
                                <button onClick={() => openEditor(entry)} className="text-gray-400 hover:text-blue-500"><Edit2 size={18}/></button>
                                <button onClick={() => handleDelete(entry.ID)} className="text-gray-400 hover:text-red-500"><Trash2 size={18}/></button>
                            </div>
                        </div>
                        <p className="text-gray-700 dark:text-gray-300 line-clamp-3">{entry.content}</p>
                    </div>
                ))}
                {entries.length === 0 && <p className="text-center text-gray-500 mt-10">No entries found. Write something!</p>}
            </div>
        )}
      </div>
    </div>
  );
}

export default App;