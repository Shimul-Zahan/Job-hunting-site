import { useContext, useState } from "react";
import { Tab, Tabs, TabList, TabPanel } from "react-tabs";
import { AuthContext } from "../../../providers/AuthProviders";
import { BiMessageDetail } from "react-icons/bi";
import { MdWorkOutline, MdLogout } from "react-icons/md";
import { BsPersonVcard } from "react-icons/bs";
import Dashboard from "./Components/Dashboard";
import AllJobs from "../SharedComponents/AllJobs";
import MyRunningJobs from "./Components/MyRunningJobs";
import { FaHistory, FaHome } from "react-icons/fa";
import History from "./Components/History";
import { Navigate, useLocation } from "react-router";
import Chat from "../../../Components/Chat";

const JobseekerDashboard = () => {
  const [activeTab, setActiveTab] = useState(0);
  const { user, logOut } = useContext(AuthContext);
  const location = useLocation();
  const from = location.state?.from?.pathname || "/";
  if (user.role !== "jobseeker") {
    return <Navigate to={from} />;
  }

  const handleLogOut = () => {
    logOut()
      .then(() => { })
      .catch((error) => console.log(error));
  };

  return (
    <div className="grid grid-cols-12">
      <div className="col-span-12 pb-20 lg:pb-0 lg:hidden">
        <div className="flex flex-col fixed items-center bg-white z-[1] mb-20 w-[89%] my-6 mx-7 p-4 custom-shadow rounded-md">
          <TabList className="flex flex-row justify-center gap-x-12 flex-wrap space-y-3">
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 0 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(0)}
            >
              <FaHome className="absolute text-xl" />
              {/* <span>Dashboard</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 1 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(1)}
            >
              <BiMessageDetail className="text-xl absolute" />
              {/* <span>Inbox</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 2 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(2)}
            >
              <MdWorkOutline className="text-xl absolute" />
              {/* <span>All Jobs</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 3 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(3)}
            >
              <BsPersonVcard className="text-xl absolute" />
              {/* <span>My Jobs</span> */}
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 4 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(4)}
            >
              <FaHistory className="text-xl absolute" />
              {/* <span>History</span> */}
            </Tab>
            <div
              onClick={handleLogOut}
              className="font-semibold cursor-pointer flex gap-2 items-center text-red-500"
            >
              <MdLogout className="text-xl absolute" />
              {/* <span>Logout</span> */}
            </div>
          </TabList>
        </div>

      </div>
      <div className="col-span-2 pb-20 lg:pb-0 hidden lg:block">

        <div className="col-span-1 flex flex-col my-6 ml-6 p-4 custom-shadow rounded-md">
          <TabList className="flex flex-col space-y-3">
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 0 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(0)}
            >
              <FaHome size="1em" />
              <span>Dashboard</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 1 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(1)}
            >
              <BiMessageDetail className="text-xl" />
              <span>Inbox</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 2 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(2)}
            >
              <MdWorkOutline className="text-xl" />
              <span>All Jobs</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 3 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(3)}
            >
              <BsPersonVcard className="text-xl" />
              <span>My Jobs</span>
            </Tab>
            <Tab
              className={`font-semibold cursor-pointer flex gap-2 items-center ${activeTab === 4 ? "text-[#1d9cb5]" : "text-black"
                }`}
              onClick={() => setActiveTab(4)}
            >
              <FaHistory className="text-xl" />
              <span>History</span>
            </Tab>
            <div
              onClick={handleLogOut}
              className="font-semibold cursor-pointer flex gap-2 items-center text-red-500"
            >
              <MdLogout className="text-xl" />
              <span>Logout</span>
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
            <AllJobs />
          </TabPanel>
          <TabPanel>
            <MyRunningJobs />
          </TabPanel>
          <TabPanel>
            <History />
          </TabPanel>
        </Tabs>
      </div>
    </div>
  );
};

export default JobseekerDashboard;
