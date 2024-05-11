import axios from "axios";
import { useEffect, useState } from "react";
import { MdOutlineEmail } from "react-icons/md";
import { SlLocationPin } from "react-icons/sl";
import { TbMessage2 } from "react-icons/tb";
import { useParams } from "react-router-dom";
import ReactHtmlParser from 'react-html-parser';

const EmployeProfile = () => {
  const [employeJobPost, setEmployeJobPost] = useState([]);
  const [approveJob, setApproveJob] = useState([]);
  const [allJobs, setAllJobs] = useState([]);
  const jobId = useParams();

  const fetchUser = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/jobPost/${jobId.id}`
      );
      setEmployeJobPost(response.data);
    } catch (error) {
      console.error("Error fetching user data:", error);
    }
  };
  const fetchData = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/job/employe/${employeJobPost?.email}`
      );
      if (response.status === 200) {
        setApproveJob(response.data);
      } else {
        console.error("Failed to fetch staff data");
      }
    } catch (error) {
      console.error("Error fetching staff data:", error);
    }
  };
  useEffect(() => {
    const url = `http://localhost:5000/myJobPosts?email=${employeJobPost?.email}`;
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        console.log(data)
        setAllJobs(data);
      })
      .catch((error) => {
        console.log(error);
      });
  }, []);

  useEffect(() => {
    fetchUser();
    fetchData();
  }, []);

  return (
    <div className="lg:w-3/4 w-11/12 mx-auto my-12">
      <div>
        <div className="grid lg:grid-cols-9 grid-cols-1 lg:gap-8 gap-y-7">
          <div className="custom-shadow p-4 lg:col-span-2 rounded-md relative">
            <div className="flex justify-center">
              <label className="avatar w-28">
                <div className="rounded-full border-2 border-white">
                  <div>
                    <img src={employeJobPost?.photoURL} alt="User Photo" />
                  </div>
                </div>
              </label>
            </div>
            <p className="text-center my-3 text-lg">Member Since: {employeJobPost?.memberSince}</p>
            <p className="text-xl  bottom-0 mx-auto w-11/12 custom-shadow text-center p-1 mb-4 capitalize">
              Employer
            </p>
          </div>
          <div className="custom-shadow rounded-md p-4 lg:col-span-7">
            <div>
              <div className="flex justify-between item relative">
                <h3 className="font-semibold text-3xl pb-2 capitalize">
                  {employeJobPost?.companyName}
                </h3>
                <div className="">
                  <button className="border-2 border-black p-2 rounded-md">
                    <TbMessage2 size="1.5em" />
                  </button>
                </div>
              </div>
              <div className="flex gap-2 items-center pb-2">
                <MdOutlineEmail className="text-3xl border border-black rounded-full p-1" />
                <p>{employeJobPost?.email}</p>
              </div>
              <div className="flex gap-2 items-center pb-2">
                <SlLocationPin className="text-3xl border border-black rounded-full p-1" />
                {employeJobPost?.location && <p>{employeJobPost?.location}</p>}
                {!employeJobPost?.location && <p>N/A</p>}
              </div>
            </div>
            <div className="pt-5"></div>
          </div>
          <div className="custom-shadow lg:col-span-9 rounded-md p-3">
            <div>
              <h4 className="font-semibold">Bio</h4>
              {employeJobPost?.about && <p>{ReactHtmlParser(employeJobPost?.about)}</p>}
              {!employeJobPost?.about && <p>N/A</p>}
            </div>
          </div>
          <div className="custom-shadow lg:col-span-9 rounded-md p-3">
            <div>
              <h4 className="text-center text-4xl font-bold">
                Company Details
              </h4>
              <br />
              <h4 className="">
                <span className="font-semibold">Company Name: </span>
                {employeJobPost?.company && (
                  <span className="capitalize">{employeJobPost?.company}</span>
                )}
                {!employeJobPost?.company && <span>N/A</span>}
              </h4>
              <h4 className="mt-2">
                <span className="font-semibold">Country: </span>
                {employeJobPost?.country && (
                  <span className="capitalize">{employeJobPost?.country}</span>
                )}
                {!employeJobPost?.country && <span>N/A</span>}
              </h4>
              <h4 className="mt-2">
              <span className="font-semibold">Industry: </span>
                {employeJobPost?.industry && (
                  <span className="capitalize">{employeJobPost?.industry}</span>
                )}
                {!employeJobPost?.industry && <span>N/A</span>}
              </h4>
              <h4 className="mt-2">
              <span className="font-semibold">Size of Company: </span>
                {employeJobPost?.companySize && (
                  <span>{employeJobPost?.companySize} Staffs</span>
                )}
                {!employeJobPost?.companySize && <span>N/A</span>}
              </h4>
              <h4 className="mt-2">
              <span className="font-semibold">Number of Job Posted: </span> <span>{allJobs?.length}</span>
              </h4>
              <h4 className="mt-2">
              <span className="font-semibold">Number of Job Approved: </span> {approveJob?.length}
              </h4>
              {/* <h4 className="font-semibold mt-2">
                Member since: <span></span>
                {employeJobPost?.memberSince && (
                  <span>{employeJobPost?.memberSince}</span>
                )}
                {!employeJobPost?.memberSince && <span>N/A</span>}
              </h4> */}
              <h4 className="mt-2">
                <span className="font-semibold">About the company: </span> <br />
                {employeJobPost?.aboutCompany && (
                  <p>{ReactHtmlParser(employeJobPost?.aboutCompany)}</p>
                )}
                {!employeJobPost?.aboutCompany && <p>N/A</p>}
              </h4>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmployeProfile;
