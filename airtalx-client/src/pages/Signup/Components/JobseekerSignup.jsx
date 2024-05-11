import Lottie from "lottie-react";
import { Link, useNavigate } from "react-router-dom";
import Jobseeker from "../../../../public/jobseeker.json";
import { useContext, useState } from "react";
import { FaGoogle } from "react-icons/fa";
import axios from "axios";
import { AuthContext } from "../../../providers/AuthProviders";
import { Button, Form, Input, message, Upload } from "antd";
import { UploadOutlined } from "@ant-design/icons";

const JobseekerSignup = () => {
  const [error, setError] = useState("");
  const { signinWithGoogle, user } = useContext(AuthContext);
  const [fileList, setFileList] = useState([]);
  const navigate = useNavigate();

  if (user) {
    console.log("role", user?.role);
    if (user?.role == "jobseeker") navigate("/jobseeker/dashboard");
    if (user?.role == "employer") navigate("/employer/dashboard");
  }

  const onFinish = async (values) => {
    try {
      const { name, email, password, confirmPassword } = values;

      // Validate password
      if (!/(?=.*[A-Z]).*[a-z]/.test(password)) {
        setError("Please add at least one uppercase and one lowercase letter");
        return;
      }

      // Check if passwords match
      if (password !== confirmPassword) {
        setError("Password and Confirm Password do not match");
        return;
      }

      const currentDate = new Date();
      const formattedDate = currentDate.toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "2-digit",
      });

      const data = new FormData();
      data.append("name", name);
      data.append("email", email);
      data.append("role", "jobseeker");
      data.append("password", confirmPassword);
      data.append("memberSince", formattedDate);
      data.append("images", fileList[0].originFileObj);

      const config = {
        headers: {
          "content-type": "multipart/form-data",
        },
      };
      const url = "http://localhost:5000/signup";
      try {
        await axios.post(url, data, config);
        message.success("Signup successful");
        navigate("/otp")
      } catch (error) {
        console.error("Signup failed:", error);
        message.error("Failed to signup. Please try again later.");
      }
    } catch (error) {
      console.error("Signup failed:", error);
      message.error("Failed to signup. Please try again later.");
    }
  };

  const onFinishFailed = (errorInfo) => {
    console.log("Failed:", errorInfo);
  };

  const normFile = (e) => {
    setFileList(e.fileList);
    // console.log(e.fileList);
    if (Array.isArray(e)) {
      return e;
    }
    return e?.fileList;
  };

  const props = {
    multiple: false,
    onRemove: (file) => {
      const index = fileList.indexOf(file);
      const newFileList = fileList.slice();
      newFileList.splice(index, 1);
      setFileList(newFileList);
    },
    beforeUpload: () => {
      return false;
    },
    fileList,
  };

  const handleGoogleLogin = () => {
    signinWithGoogle()
      .then((result) => {
        const person = result?.user;
        console.log("🚀 ~ .then ~ person:", person);

        const currentDate = new Date();
        const formattedDate = currentDate.toLocaleDateString("en-US", {
          year: "numeric",
          month: "long",
          day: "2-digit",
        });

        if (person) {
          const userData = {
            name: person?.displayName,
            email: person?.email,
            role: "jobseeker",
            password: "",
            photoURL: person?.photoURL,
            memberSince: formattedDate
          };

          axios
            .post("http://localhost:5000/google/signup", userData, {
              headers: {
                "Content-Type": "application/json",
              },
            })
            .then((response) => {
              console.log("🚀 ~ .then ~ response:", response.data);
              if (!response) {
                message.error("Failed to Signup");
              }
              message.success("SignUp successful");

              localStorage.setItem("access-token", response.data?.token);
              if (response?.data?.user?.role == "jobseeker")
                navigate("/jobseeker/dashboard");
              if (response?.data?.user?.role == "employer")
                navigate("/employer/dashboard");

              navigate("/login");
            })
            .catch((error) => {
              console.error("Error posting user data:", error);
            });
        }
      })
      .catch((error) => {
        console.error("Google sign-in error:", error.message);
      });
  };

  return (
    <div>
      <div className="flex justify-between items-center gap-20 py-12">
        <div className="w-full md:block hidden">
          <Lottie animationData={Jobseeker} />
        </div>
        <div className="w-[600px] mt-12 bg-[#edf7f4] custom-shadow rounded-lg p-8 mb-4">
          <h2 className="text-xl text-center font-semibold mb-3 uppercase">
            Jobseeker Signup
          </h2>
          <Form
            name="jobseeker_signup"
            initialValues={{ remember: true }}
            onFinish={onFinish}
            onFinishFailed={onFinishFailed}
          >
            <label htmlFor="">Name</label>
            <Form.Item
              // label="Name"
              name="name"
              rules={[{ required: true, message: "Please input your name!" }]}
            >
              <Input className="bg-[#f5f5f5] rounded p-2 border-slate-300 border w-full" />
            </Form.Item>
            <label htmlFor="">Email</label>
            <Form.Item
              // label="Email"
              name="email"
              rules={[{ required: true, message: "Please input your email!" }]}
            >
              <Input className="bg-[#f5f5f5] rounded p-2 border-slate-300 border w-full" />
            </Form.Item>
            <label htmlFor="">Password</label>
            <Form.Item
              // label="Password"
              name="password"
              rules={[
                { required: true, message: "Please input your password!" },
              ]}
            >
              <Input.Password className="bg-[#f5f5f5] rounded p-2 border-slate-300 border w-full" />
            </Form.Item>
            <label htmlFor="">Confirm Password</label>
            <Form.Item
              // label="Confirm Password"
              name="confirmPassword"
              rules={[
                { required: true, message: "Please confirm your password!" },
              ]}
            >
              <Input.Password className="bg-[#f5f5f5] rounded p-2 border-slate-300 border w-full" />
            </Form.Item>
            <label htmlFor="">Image</label>
            <Form.Item
              name="user_image"
              valuePropName="fileList"
              // label="Image"
              getValueFromEvent={normFile}
              rules={[
                {
                  required: true,
                  message: "Please upload a Image!",
                },
              ]}
            >
              <Upload
                name="logo"
                action="/upload.do"
                listType="picture"
                {...props}
              >
                <Button className="p-2 h-10" icon={<UploadOutlined />}>
                  Click to upload Image
                </Button>
              </Upload>
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                className="w-full bg-[#1d9cb5] rounded text-white font-semibold h-10 mt-3"
              >
                Signup
              </Button>
            </Form.Item>
          </Form>
          <div className="text-center">
            <small>
              Already have an account?{" "}
              <Link to="/login" className="text-[#1d7edd] font-semibold">
                Login Now
              </Link>
            </small>
          </div>
          <div className="flex text-center gap-2 mb-3">
            <Button
              onClick={handleGoogleLogin}
              className="w-full border-[#1d9cb5] border rounded font-semibold h-10 mt-3 flex justify-center items-center gap-3"
            >
              <FaGoogle />
              <span>Continue with Google</span>
            </Button>
          </div>
          <p className="text-center pt-8 text-red-700 font-semibold">{error}</p>
        </div>
      </div>
    </div>
  );
};

export default JobseekerSignup;
