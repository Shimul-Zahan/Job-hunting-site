import { useContext, useEffect, useState } from "react";
import { AuthContext } from "../../../../providers/AuthProviders";
import { RiDeleteBin6Line } from "react-icons/ri";
import axios from "axios";
import { Link } from "react-router-dom";
import { message } from "antd";
import { TbMessage2 } from "react-icons/tb";

const Dashboard = () => {
  const { user } = useContext(AuthContext);
  const [approveJob, setApproveJob] = useState([]);
  const [jobPost, setJobPost] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [ApproveJobsPerPage] = useState(6);

  const fetchData = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/job/employe/${user?.email}`
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

  const fetchJobPostData = async () => {
    try {
      const response = await axios.get(
        `http://localhost:5000/jobPost/employe/${user?.email}`
      );
      if (response.status === 200) {
        setJobPost(response.data);
      } else {
        console.error("Failed to fetch job posts");
      }
    } catch (error) {
      console.error("Error fetching job posts:", error);
    }
  };

  const handleMakeCancelled = (email, jobId) => {
    axios
      .patch(`http://localhost:5000/appliedJob/updateProjectStatus/${email}`, {
        jobId: jobId,
        projectStatus: "cancelled",
      })
      .then((response) => {
        if (response.status === 200) {
          message.error("Job application Cancelled!");
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
  const handleProjectStatus = (email, jobId) => {
    axios
      .patch(`http://localhost:5000/appliedJob/updateProjectStatus/${email}`, {
        jobId: jobId,
        projectStatus: "Completed",
      })
      .then((response) => {
        if (response.status === 200) {
          message.success("ProjectStatus Updated!");
          fetchData();
        } else {
          message.error("Failed to update ProjectStatus application");
        }
      })
      .catch((error) => {
        console.error("Error updating application status:", error);
        message.error("Failed to reject application");
      });
  };

  useEffect(() => {
    fetchData();
    fetchJobPostData();
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
  const indexOfLastFlat = currentPage * ApproveJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - ApproveJobsPerPage;
  const currentJobs = approveJob.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <div className="p-6">
      <div className="grid lg:grid-cols-3 grid-cols-1 lg:gap-7">
        <div className="flex justify-between custom-shadow p-4 rounded-md mb-7">
          <div className="">
            <h4 className="text-2xl font-semibold">Hello {user?.name}</h4>
            <p>{"Here's what's going on"}</p>
          </div>
        </div>
        <div className="flex justify-between items-center custom-shadow p-4 rounded-md mb-7">
          <h4 className="text-2xl font-semibold">
            Total Staff: {approveJob.length}
          </h4>
        </div>
        <div className="flex justify-between items-center custom-shadow p-4 rounded-md mb-7">
          <h4 className="text-2xl font-semibold">
            Total Job Posted: {jobPost.length}
          </h4>
        </div>
      </div>
      <div className="block lg:hidden">
        <div className="grid grid-cols-1">
          <div className="flex justify-between">
            <h4 className="text-2xl font-semibold pb-4">Staff Pannel</h4>
          </div>
          {
            currentJobs.map(job => <div className="custom-shadow p-4 rounded-md" key={job?.jobData?._id}>
              <div className="flex justify-between items-center">
                <p className="text-2xl">{job?.userEmail}</p>
                <p>{job?.jobData?.jobType}</p>
              </div>
              <p>{job?.jobData?.jobTitle}</p>
              <p>{job?.jobData?.salary}</p>
            </div>)
          }
        </div>
      </div>
      <div className="custom-shadow hidden lg:block p-4 rounded-md">
        <div className="flex justify-between">
          <h4 className="text-2xl font-semibold">Staff Pannel</h4>
        </div>
        <div className="overflow-x-auto">
          <table className="table w-full">
            {/* head */}
            <thead>
              <tr className="font-semibold text-base text-center">
                <th>No.</th>
                <th>Staff Email</th>
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
                      <div className=" flex flex-col gap-2">
                        <button
                          className="btn btn-success btn-sm text-white w-32"
                          onClick={() => handleProjectStatus(job?.userEmail, job?.jobId)}
                        >
                          Complete
                        </button>
                        <button
                          className="btn btn-error btn-sm text-white"
                          onClick={() =>
                            handleMakeCancelled(job?.userEmail, job?.jobId)
                          }
                        >
                          <RiDeleteBin6Line size="1.2em" />
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
            { length: Math.ceil(approveJob.length / ApproveJobsPerPage) },
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
              currentPage === Math.ceil(approveJob.length / ApproveJobsPerPage)
            }
          >
            Next &rarr;
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
