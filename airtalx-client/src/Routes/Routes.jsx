import { createBrowserRouter } from "react-router-dom";
import Main from "../Layout/Main";
import Home from "../pages/Home/Home";
import Login from "../pages/Login/Login";
import Signup from "../pages/Signup/Signup";
import JobseekerDashboard from "../pages/AllDashboard/JobseekerDashboard/JobseekerDashboard";
import EmployerDashboard from "../pages/AllDashboard/EmployerDashboard/EmployerDashboard";
import AdminDashboard from "../pages/AllDashboard/AdminDashboard/AdminDashboard";
import JobDetails from "../pages/AllDashboard/SharedComponents/JobDetails";
import Profile from "../pages/Profile/Profile";
import FindJob from "../pages/Find Job/FindJob";
import UserProfile from "../pages/Users/UserProfile";
import PrivateRouter from "./PrivateRouter";
import ForgotPassword from "../pages/ForgotPassword/ForgotPassword";
import ResetPassword from "../pages/ForgotPassword/ResetPassword/ResetPassword";
import EmployeProfile from "../pages/EmployeProfile/EmployeProfile";
import FindEmployee from "../pages/FindEmploye/FindEmployee";
import UpdateProfile from "../pages/UpdateProfile/UpdateProfile";
import OtpUI from "../pages/OtpUI/OtpUI";
import AboutUs from "../pages/Shared/AboutUs";
import Blogs from "../pages/Blogs/Blogs";
import ContactUs from "../pages/ContactUs/ContactUs";
import BlogDetails from "../pages/Blogs/BlogDetails";
import TermsOfUse from "../pages/TermsOfUse/TermsOfUse";
import PrivacyAndPolicy from "../pages/PrivacyAndPolicy/PrivacyAndPolicy";
import HelpAndFAQs from "../pages/HelpAndFAQs/HelpAndFAQs";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Main />,
    children: [
      {
        path: "/",
        element: <Home />,
      },
      {
        path: "/profile",
        element: <PrivateRouter><Profile /></PrivateRouter>,
      },
      {
        path: "/updateProfile",
        element: <PrivateRouter><UpdateProfile /></PrivateRouter>,
      },
      {
        path: "/otp",
        element: <OtpUI />,
      },
      {
        path: '/jobseekerProfile/:name/:id',
        element: <PrivateRouter><UserProfile /></PrivateRouter>
      },
      {
        path: '/employeProfile/:name/:id',
        element: <PrivateRouter><EmployeProfile /></PrivateRouter>
      },
      {
        path: '/forgot-password',
        element: <ForgotPassword />
      },
      {
        path: "/reset_password/:id/:token",
        element: <ResetPassword />
      },
      {
        path: "/findJob",
        element: <FindJob />,
      },
      {
        path: "/findEmployee",
        element: <FindEmployee />,
      },
      {
        path: "/contactus",
        element: <ContactUs />,
      },
      {
        path: "/jobseeker/dashboard",
        element: <PrivateRouter><JobseekerDashboard /></PrivateRouter>,
      },
      {
        path: "/employer/dashboard",
        element: <PrivateRouter><EmployerDashboard /></PrivateRouter>,
      },
      {
        path: "/admin/dashboard",
        element: <PrivateRouter><AdminDashboard /></PrivateRouter>,
      },
      {
        path: "/jobdetails/:jobTitle/:id",
        element: <JobDetails />,
      },
      {
        path: "/login",
        element: <Login />,
      },
      {
        path: "/signup",
        element: <Signup />,
      },
      {
        path: "/aboutUs",
        element: <AboutUs />,
      },
      {
        path: "/termsOfUse",
        element: <TermsOfUse />,
      },
      {
        path: "/privacyAndPolicy",
        element: <PrivacyAndPolicy />,
      },
      {
        path: "/helpAndFAQs",
        element: <HelpAndFAQs />,
      },
      {
        path: "/blogs",
        element: <Blogs />,
      },
      {
        path: "/blogDetails/:blogTitle/:id",
        element: <BlogDetails />,
      },
    ],
  },
]);
