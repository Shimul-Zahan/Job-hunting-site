import Lottie from "lottie-react";
import LoginModel from "../../../public/login-model.json";
import { Link, useNavigate } from "react-router-dom";
import { FaGoogle } from "react-icons/fa";
import { useContext, useState } from "react";
import { AuthContext } from "../../providers/AuthProviders";
import axios from "axios";
import { message } from "antd";

const Login = () => {
  const { signinWithGoogle, login, user, setUser } = useContext(AuthContext);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleLogin = async (event) => {
    event.preventDefault();

    const form = event.target;
    const email = form.email.value;
    const password = form.password.value;
    console.log(email, password);

    try {
      await login(email, password);
    } catch (error) {
      message.error(error.response.data.message);
    }
  };

  const handleGoogleLogin = async () => {
    try {
      const result = await signinWithGoogle();
      const user = result.user;
      const response = await axios.get(
        `http://localhost:5000/users/google/${user?.email}`
      );
      const { token, user: userData } = response.data;
      if (userData) {
        console.log("🚀 ~ handleGoogleLogin ~ userData:", userData)
        setUser(userData);
        localStorage.setItem("access-token", token);
        if (userData?.role === "jobseeker") {
          navigate("/jobseeker/dashboard");
        } else if (userData?.role === "employer") {
          navigate("/employer/dashboard");
        } else if (userData?.role === "admin") {
          navigate("/admin/dashboard");
        }
      }
      // message.success("Login Successful!"); // Uncomment if you want to show a success message
    } catch (error) {
      if (error.response) {
        message.error(error.response.data.message);
      } else {
        console.error("Google sign-in error:", error.message);
      }
    }
  };

  if (user) {
    console.log("role", user?.role);
    if (user?.role == "jobseeker") navigate("/jobseeker/dashboard");
    if (user?.role == "employer") navigate("/employer/dashboard");
    if (user?.role == "admin") navigate("/admin/dashboard");
  }
  return (
    <div className="lg:w-2/3 w-11/12 mx-auto">
      <div className="flex justify-between gap-20 md:py-36 py-12">
        <div className="w-full md:block hidden">
          <Lottie animationData={LoginModel} />
        </div>
        <div className="w-[600px] bg-[#edf7f4] custom-shadow rounded-lg p-8 mb-4">
          <h2 className="text-4xl text-center font-semibold mb-3 uppercase">
            Login
          </h2>
          <form onSubmit={handleLogin}>
            <div className="flex flex-col gap-5">
              <div className="pb-2">
                <label htmlFor="email">Email</label>
                <br />
                <input
                  className="bg-[#f5f5f5] rounded p-2 border-slate-300 border w-full"
                  type="email"
                  name="email"
                  id=""
                  required
                />
              </div>
              <div className="pb-2">
                <label htmlFor="password">Password</label>
                <br />
                <input
                  className="bg-[#f5f5f5] rounded p-2 border-slate-300 border w-full"
                  type="password"
                  name="password"
                  id=""
                  required
                />
              </div>
              <div className="flex gap-2 mb-3">
                <button className="w-full bg-[#1d9cb5] rounded text-white font-semibold p-2 mt-3">
                  Login
                </button>
              </div>
            </div>
          </form>
          <p className="text-center">--------- or ---------</p>
          <div className="flex text-center gap-2 mb-3">
            <button
              onClick={handleGoogleLogin}
              className="w-full border-[#1d9cb5] border rounded font-semibold p-2 mt-3 flex justify-center items-center gap-3"
            >
              <FaGoogle />
              <span>Continue with Google</span>
            </button>
          </div>
          <div className="text-center">
            <small>
              Do not have an account?{" "}
              <Link to="/signup" className="text-[#1d7edd] font-semibold">
                Signup now
              </Link>
            </small>
            <br />
            <Link to="/forgot-password" className="link link-primary">Forgot Password</Link>
          </div>
          <p className="text-center pt-8 text-red-700 font-semibold">{error}</p>
        </div>
      </div>
    </div>
  );
};

export default Login;
