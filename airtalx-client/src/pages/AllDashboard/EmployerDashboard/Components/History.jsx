import axios from "axios";
import { useContext, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AuthContext } from "../../../../providers/AuthProviders";
import { message } from "antd";

const History = () => {
  const { user } = useContext(AuthContext);
  const [currentPage, setCurrentPage] = useState(1);
  const [historyJobsPerPage] = useState(6);
  const [historyJob, setHistoryJob] = useState([]);

  const fetchData = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/job/employe/history/${user?.email}`
      );
      if (response.status === 200) {
        setHistoryJob(response.data);
      } else {
        message.error("Failed to fetch Applicant data");
      }
    } catch (error) {
      console.error("Error fetching staff data:", error);
    }
  };
  useEffect(() => {
    fetchData();
  }, []);

  const getBadgeClass = (role) => {
    switch (role) {
      case "approved":
        return "badge-accent";
      case "cancelled":
        return "badge-error";
      case "Completed":
        return "badge-success";
      default:
        return "";
    }
  };

  // Logic for pagination
  const indexOfLastFlat = currentPage * historyJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - historyJobsPerPage;
  const currentJobs = historyJob.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <div className="p-6">
      <div className="lg:hidden block">
        <div className="flex pb-4 justify-between">
          <h4 className="text-2xl font-semibold">History</h4>
        </div>
        {
          currentJobs.map(job => <div className="custom-shadow p-4 rounded-md" key={job?.jobData?._id}>
            <div className="flex justify-between items-center">
              <p className="text-2xl">{job?.userEmail}</p>
              <p>{job?.jobData?.jobType}</p>
            </div>
            <p>{job?.jobData?.jobTitle}</p>
            <p>{job?.jobData?.salary}</p>
            <div
              className={`badge ${getBadgeClass(
                job?.status
              )} badge-md text-white`}
            >
              {job?.status}
            </div>
            <div className="text-red-700 text-xl cursor-pointer"></div>
            <Link to={`/user/${job?.userEmail}`} className="text-[#1d9cb5] font-semibold">
              <button className="">
                Details
              </button>
            </Link>
          </div>)
        }
      </div>
      <div className="custom-shadow lg:block hidden p-4 rounded-md">
        <div className="flex justify-between">
          <h4 className="text-2xl font-semibold">History</h4>
        </div>
        <div className="overflow-x-auto">
          <table className="table w-full">
            {/* head */}
            <thead>
              <tr className="font-semibold text-base text-center">
                <th>No.</th>
                <th>Applicant Email</th>
                <th>Job Title</th>
                <th>Job Type</th>
                <th>Salary</th>
                <th>Status</th>
                <th>Project Status</th>
                <th>Applicant Details</th>
              </tr>
            </thead>
            <tbody className="text-center">
              {currentJobs.map((job, index) => (
                <tr key={job?.jobData?._id}>
                  <td>{index + 1}</td>
                  <td>{job?.userEmail}</td>
                  <td>{job?.jobData?.jobTitle}</td>
                  <td>{job?.jobData?.jobType}</td>
                  <td>{job?.jobData?.salary}</td>
                  <td>
                    <div
                      className={`badge ${getBadgeClass(
                        job?.status
                      )} badge-md text-white`}
                    >
                      {job?.status}
                    </div>
                  </td>
                  <td>
                    <div
                      className={`badge ${getBadgeClass(
                        job?.projectStatus
                      )} badge-md text-white`}
                    >
                      {job?.projectStatus}
                    </div>
                  </td>
                  <td>
                    <Link to={`/user/${job?.userEmail}`} className="text-[#1d9cb5] font-semibold">
                      <button className="">
                        Details
                      </button>
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {/* for pagination */}
        <div className=" flex flex-wrap justify-center mb-10 mt-5">
          <button
            className="join-item btn btn-outline mr-2"
            onClick={() => paginate(currentPage - 1)}
            disabled={currentPage === 1}
          >
            &larr; Previous page
          </button>
          {Array.from(
            { length: Math.ceil(historyJob.length / historyJobsPerPage) },
            (_, i) => (
              <button
                key={i}
                onClick={() => paginate(i + 1)}
                className={`join-item btn btn-outline mr-2 ${currentPage === i + 1 ? "bg-green-400 text-white" : ""
                  }`}
              >
                {i + 1}
              </button>
            )
          )}
          <button
            className="join-item btn btn-outline mr-2"
            onClick={() => paginate(currentPage + 1)}
            disabled={
              currentPage === Math.ceil(historyJob.length / historyJobsPerPage)
            }
          >
            Next &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};

export default History;
