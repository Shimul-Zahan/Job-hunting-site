import { useContext, useState } from "react";
import { Tab, Tabs, TabList, TabPanel } from "react-tabs";
import { AuthContext } from "../../../providers/AuthProviders";
import { AiOutlineHome, AiOutlineProfile } from "react-icons/ai";
import { BiMessageDetail } from "react-icons/bi";
import { MdWorkOutline, MdLogout } from "react-icons/md";
import { BsFilePerson, BsPersonVcard } from "react-icons/bs";
import Dashboard from "./Components/Dashboard";
import PostJob from "./Components/PostJob";
import MyJobs from "./Components/MyJobs";
import Applicant from "./Components/Applicant";
import Alljobseekers from "./Components/Alljobseekers";
import History from "./Components/History";
import { FaHistory } from "react-icons/fa";
import { Navigate, useLocation } from "react-router";
import Chat from "../../../Components/Chat";
const EmployerDashboard = () => {
  const [activeTab, setActiveTab] = useState(0);
  const { user, logOut } = useContext(AuthContext);
  const location = useLocation();
  const from = location.state?.from?.pathname || "/";
  if (user.role !== "employer") {
    return <Navigate to={from} />;
  }
  const handleLogOut = () => {
    logOut()
      .then(() => { })
      .catch((error) => console.log(error));
  };
  return (
    <div className="grid grid-cols-12">
      <div className="col-span-12 lg:col-span-1 pb-20 lg:pb-0 lg:hidden block">
        <div className="flex flex-col fixed items-center bg-white z-[1] mb-20 w-full pr-2 my-6 mx-7 p-4 custom-shadow rounded-md">
          <TabList className="flex flex-row justify-center gap-x-12 flex-wrap space-y-3">
            <Tab
              className={`font-semibold cursor-pointer flex items-center ${activeTab === 0 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(0)}
            >
              <AiOutlineHome className="text-xl absolute" />
              {/* <span className="pl-7">Dashboard</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 1 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(1)}
            >
              <BiMessageDetail className="text-xl absolute" />
              {/* <span className="pl-7">Inbox</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 2 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(2)}
            >
              <AiOutlineProfile className="text-xl absolute" />
              {/* <span className="pl-7">Post a Job</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 3 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(3)}
            >
              <BsFilePerson className="text-xl absolute" />
              {/* <span className="pl-7">Applicants</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 4 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(4)}
            >
              <FaHistory className="text-xl absolute" />
              {/* <span className="pl-7">History</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 5 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(5)}
            >
              <MdWorkOutline className="text-xl absolute" />
              {/* <span className="pl-7">All Workers</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 6 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(6)}
            >
              <BsPersonVcard className="text-xl absolute" />
              {/* <span className="pl-7">My Jobs</span> */}
            </Tab>
            <div
              onClick={handleLogOut}
              className="font-semibold cursor-pointer flex gap-2 items-center text-red-500"
            >
              <MdLogout className="text-xl absolute" />
              {/* <span className="pl-7">Logout</span> */}
            </div>
          </TabList>
        </div>
      </div>
      <div className="col-span-2 hidden lg:block">
        <div className="flex flex-col my-6 ml-7 p-4 custom-shadow rounded-md">
          <TabList className="flex flex-col space-y-3">
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 0 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(0)}
            >
              <AiOutlineHome className="text-xl absolute" />
              <span className="pl-7">Dashboard</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 1 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(1)}
            >
              <BiMessageDetail className="text-xl absolute" />
              <span className="pl-7">Inbox</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 2 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(2)}
            >
              <AiOutlineProfile className="text-xl absolute" />
              <span className="pl-7">Post a Job</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 3 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(3)}
            >
              <BsFilePerson className="text-xl absolute" />
              <span className="pl-7">Applicants</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 4 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(4)}
            >
              <FaHistory className="text-xl absolute" />
              <span className="pl-7">History</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 5 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(5)}
            >
              <MdWorkOutline className="text-xl absolute" />
              <span className="pl-7">All Workers</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 6 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(6)}
            >
              <BsPersonVcard className="text-xl absolute" />
              <span className="pl-7">My Jobs</span>
            </Tab>
            <div
              onClick={handleLogOut}
              className="font-semibold cursor-pointer flex gap-2 items-center text-red-500"
            >
              <MdLogout className="text-xl absolute" />
              <span className="pl-7">Logout</span>
            </div>
          </TabList>
        </div>
      </div>
      <div className="lg:col-span-10 col-span-12">
        <Tabs selectedIndex={activeTab}>
          <TabPanel>
            <Dashboard />
          </TabPanel>
          <TabPanel>
            <Chat />
          </TabPanel>
          <TabPanel>
            <PostJob />
          </TabPanel>
          <TabPanel>
            <Applicant />
          </TabPanel>
          <TabPanel>
            <History />
          </TabPanel>
          <TabPanel>
            <Alljobseekers />
          </TabPanel>
          <TabPanel>
            <MyJobs />
          </TabPanel>
        </Tabs>
      </div>
    </div>
  );
};

export default EmployerDashboard;
