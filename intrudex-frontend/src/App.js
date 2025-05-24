import React, { useState } from "react";
import Login from "./Login"; 
import Scan from "./Scan";   

function App() {
  const [token, setToken] = useState(localStorage.getItem("token"));

  const saveToken = (token) => {
    localStorage.setItem("token", token);
    setToken(token);
  };

  const logout = () => {
    localStorage.removeItem("token");
    setToken(null);
  };

  return (
    <div className="App">
      {!token ? (
        <Login setToken={saveToken} />
      ) : (
        <>
          <button onClick={logout} style={{ float: "right", margin: "10px" }}>Logout</button>
          <Scan token={token} />
        </>
      )}
    </div>
  );
}

export default App;




