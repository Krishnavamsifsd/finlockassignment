import "./App.css";
import { useState, useEffect } from "react";
import axios from "./axios";
function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [cookieValue, setCookieValue] = useState("");

  useEffect(() => {
    axios.get("/").then((result) => {
      setCookieValue(result.data);
      console.log(result);
    });
  }, []);

  function submit(e) {
    e.preventDefault();
    axios
      .post("/", {
        email: email,
        password: password,
      })
      .then((result) => {
        alert(result.data);
        window.location.href = "/";
        console.log(result);
      })
      .catch((e) => {
        console.log(e);
      });
    setEmail("");
    setPassword("");
  }

  return (
    <div className="app">
      <div className="circle__background">
        <div className="img"></div>
      </div>
      {cookieValue ? (
        <h1 className="title1">Welcome! {cookieValue}</h1>
      ) : (
        <>
          <h1 className="title">Welcome!</h1>
          <p className="first__p">Let's connect to your workspace. </p>
          <p className="second__p">
            Please enter your credentials to continue.
          </p>

          <input
            type="text"
            placeholder="Email Address"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <span className="img__eye"></span>
          <button className="button" onClick={(e) => submit(e)}>
            Sign In
          </button>
        </>
      )}
    </div>
  );
}

export default Login;
