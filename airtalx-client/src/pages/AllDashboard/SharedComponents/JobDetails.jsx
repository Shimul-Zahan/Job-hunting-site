import { useContext, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { AuthContext } from "../../../providers/AuthProviders";
import { message } from "antd";
import ReactHtmlParser from 'react-html-parser';

const JobDetails = () => {
  const { user } = useContext(AuthContext);
  const jobDescription = useParams();
  console.log("🚀 ~ JobDetails ~ jobDescription:", jobDescription.id)
  const [jobData, setJobData] = useState([]);
  useEffect(() => {
    const url = "http://localhost:5000/newJobPost";
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        const jobData = data.find((job) => job._id === jobDescription.id);
        setJobData(jobData);
        console.log(jobData);
      })
      .catch((error) => {
        console.log(error);
      });
  }, []);

  const handleApply = async (data) => {
    try {
      const response = await fetch(
        `http://localhost:5000/applyJob/${user?.email}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            jobId: data?._id,
            employeEmail: data.email,
            jobData: data,
          }),
        }
      );

      const responseData = await response.json();

      if (responseData.message) {
        message.success(responseData.message);
      } else {
        message.error(responseData.error);
      }
    } catch (error) {
      message.error(error);
    }
  };
  
  return (
    <div className="lg:w-3/4 w-11/12 mx-auto">
      <div className="flex justify-between">
        <div className="pt-20">
          <h3 className="text-4xl font-semibold lg:w-3/4 pb-2">
            {jobData?.headline}
          </h3>
          <div>
            <span>by</span>
            <span className="text-[#1d9cb5] capitalize font-semibold pl-1">
              {jobData?.companyName}
            </span>
          </div>
          <div>
            <button
              className={`text-xl rounded mt-3 px-6 py-1 ${user?.role === "employer" || user?.role === "admin" || !user
                  ? "bg-gray-500 text-gray-300 cursor-not-allowed"
                  : "bg-[#1d9cb5] text-white"
                }`}
              onClick={() => handleApply(jobData)}
              disabled={user?.role === "employer" || user?.role === "admin" || !user}
            >
              {user ? "Apply" : "Login to Apply Job"}
            </button>
          </div>
        </div>
        <div className="w-1/4">
          <img src="/job-details-img.svg" alt="" />
        </div>
      </div>
      <div className="pb-12">
        <h4 className="text-5xl font-semibold text-center pb-6">Job Details</h4>
        <div className="flex justify-center gap-10">
          <div className="text-center custom-shadow p-10 rounded-md w-96">
            <p>JOB TITLE</p>
            <h4 className="text-2xl font-semibold">{jobData?.jobTitle}</h4>
          </div>
          <div className="text-center custom-shadow p-10 rounded-md w-96">
            <p>JOB RATE PER HOUR</p>
            <div className="flex items-center justify-center gap-2">
              <h4 className="text-2xl font-semibold">${jobData?.startingSalary}/hr</h4> - 
              <h4 className="text-2xl font-semibold">${jobData?.endingSalary}/hr</h4>
            </div>
          </div>
          <div className="text-center custom-shadow p-10 rounded-md w-96">
            <p>EMPLOYMENT</p>
            <h4 className="text-2xl font-semibold">{jobData?.jobType}</h4>
          </div>
        </div>
      </div>
      <div className="pb-12">
        <h4 className="text-5xl font-semibold text-center pt-8 pb-6">
          Job Description
        </h4>
        <div className="first-letter:capitalize">{ReactHtmlParser(jobData?.jobDescription)}</div>
      </div>
      <div className="pb-12">
        <h4 className="text-5xl font-semibold text-center pt-8 pb-6">
          About Company
        </h4>
        <div className="first-letter:capitalize">{ReactHtmlParser(jobData?.aboutCompany)}</div>
      </div>
    </div>
  );
};

export default JobDetails;
