import axios from "axios";
import { useContext, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { AuthContext } from "../../../../providers/AuthProviders";
import { message } from "antd";
import { TbMessage2 } from "react-icons/tb";

const Applicant = () => {
  const { user } = useContext(AuthContext);
  const [currentPage, setCurrentPage] = useState(1);
  const [pendingJobsPerPage] = useState(6);
  const [pendingJob, setPendingJob] = useState([]);
  const fetchData = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/job/employe/pending/${user?.email}`
      );
      if (response.status === 200) {
        setPendingJob(response.data);
      } else {
        console.error("Failed to fetch staff data");
      }
    } catch (error) {
      console.error("Error fetching staff data:", error);
    }
  };

  const handleMakeApproved = (email, jobId) => {
    axios
      .patch(`http://localhost:5000/appliedJob/updateStatus/${email}`, {
        jobId: jobId,
        status: "approved",
      })
      .then((response) => {
        console.log("🚀 ~ .then ~ response:", response)
        if (response.status === 200) {
          message.success(response.data.message);
          fetchData();
        } else {
          message.error("Failed to approve application");
        }
      })
      .catch((error) => {
        console.error("Error updating application status:", error);
        message.error("Failed to approve application");
      });
  };
  const handleMakeReject = (email, jobId) => {
    axios.patch(`http://localhost:5000/appliedJob/updateStatus/${email}`, {
      jobId: jobId,
      status: "rejected",
    })
      .then((response) => {
        if (response.status === 200) {
          message.error("Job application Rejected!");
          fetchData();
        } else {
          message.error("Failed to reject application");
        }
      })
      .catch((error) => {
        console.error("Error updating application status:", error);
        message.error("Failed to reject application");
      });
  };

  useEffect(() => {
    fetchData();
  }, []);

  const getBadgeClass = (role) => {
    switch (role) {
      case "approved":
        return "badge-accent";
      case "pending":
        return "badge-warning";
      default:
        return "";
    }
  };

  // Logic for pagination
  const indexOfLastFlat = currentPage * pendingJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - pendingJobsPerPage;
  const currentJobs = pendingJob.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <div className="p-6">
      <div className="block lg:hidden">
        <div className="grid grid-cols-1">
          <div className="flex justify-between">
            <h4 className="text-2xl font-semibold pb-4">Applicants</h4>
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
              <div className=" flex flex-col gap-2">
                <button
                  className="btn btn-success btn-sm text-white w-32"
                  onClick={() => handleMakeApproved(job.userEmail, job.jobId)}
                >
                  Approve
                </button>
                <button
                  className="btn btn-error btn-sm text-white w-32"
                  onClick={() => handleMakeReject(job.userEmail, job.jobId)}
                >
                  Cancel
                </button>
              </div>
              <Link to={`/user/${job?.userEmail}`} className="text-[#1d9cb5] font-semibold">
                <button className="">
                  Details
                </button>
              </Link>
            </div>)
          }
        </div>
      </div>
      <div className="custom-shadow lg:block hidden p-4 rounded-md">
        <div className="flex justify-between">
          <h4 className="text-2xl font-semibold pb-4">Applicants</h4>
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
                <th>Details</th>
                <th>Contact</th>
                <th>Action</th>
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
                    <Link to={`/user/${job?.userEmail}`} className="text-[#1d9cb5] font-semibold">
                      <button className="">
                        Details
                      </button>
                    </Link>
                  </td>
                  <td>
                    <div className="flex justify-center cursor-pointer">
                      <TbMessage2 className="border border-black text-3xl p-1 rounded-md" />
                    </div>
                  </td>
                  <td>
                    <div className="flex justify-center">
                      <div className="text-red-700 text-xl cursor-pointer"></div>
                      <div className=" flex flex-col gap-2">
                        <button
                          className="btn btn-success btn-sm text-white w-32"
                          onClick={() => handleMakeApproved(job.userEmail, job.jobId)}
                        >
                          Approve
                        </button>
                        <button
                          className="btn btn-error btn-sm text-white w-32"
                          onClick={() => handleMakeReject(job.userEmail, job.jobId)}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
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
            { length: Math.ceil(pendingJob.length / pendingJobsPerPage) },
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
              currentPage === Math.ceil(pendingJob.length / pendingJobsPerPage)
            }
          >
            Next &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};

export default Applicant;
