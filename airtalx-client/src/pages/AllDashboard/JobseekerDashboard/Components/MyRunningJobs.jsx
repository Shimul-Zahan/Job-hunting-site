import { useContext, useEffect, useState } from "react";
import { SlWallet } from "react-icons/sl";
import { Link } from "react-router-dom";
import { AuthContext } from "../../../../providers/AuthProviders";
import axios from "axios";

const MyRunningJobs = () => {
  const { user } = useContext(AuthContext);
  const [allJobs, setAllJobs] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [MyAllJobsPerPage] = useState(6);
  const fetchAppliedJobs = async () => {
    try {
      const response = await axios.post(
        `http://localhost:5000/appliedJob/jobseeker/all/${user?.email}`
      );
      if (response.status === 200) {
        setAllJobs(response.data);
      } else {
        throw new Error("Failed to fetch applied jobs.");
      }
    } catch (error) {
      console.error("Error fetching applied jobs:", error);
    }
  };

  useEffect(() => {
    fetchAppliedJobs();
  }, []);

  // Logic for pagination
  const indexOfLastFlat = currentPage * MyAllJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - MyAllJobsPerPage;
  const currentJobs = allJobs.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const getBadgeClass = (role) => {
    switch (role) {
      case "approved":
        return "badge-accent";
      case "cancelled":
        return "badge-error";
      case "Completed":
        return "badge-success";
      case "pending":
        return "badge-warning";
      default:
        return "";
    }
  };
  return (
    <>
      <div className="grid lg:grid-cols-3 grid-cols-1 m-3">
        {currentJobs.map((singleJob) => (
          <div className="custom-shadow m-3 p-4 rounded-md" key={singleJob?.jobData?._id}>
            <div>
              <div className="flex justify-between items-center pb-4">
                <div>
                  <h3 className="text-2xl font-semibold">
                    {singleJob?.jobData?.jobTitle}
                  </h3>
                  <p>
                    by{" "}
                    <Link to={`/user/${singleJob?.jobData?.email}`}>
                      <span className="text-[#1d9cb5] font-semibold cursor-pointer">
                        {singleJob?.jobData?.companyName}
                      </span></Link>
                  </p>
                </div>
                <p className="border border-black rounded-md font-semibold p-2">
                  {singleJob?.jobData?.jobType}
                </p>
              </div>
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex gap-2 items-center text-lg font-semibold">
                    <SlWallet />
                    <p>{singleJob?.jobData?.salary}</p>
                  </div>
                  <div
                    className={`badge ${getBadgeClass(
                      singleJob?.status
                    )} badge-md text-white`}
                  >
                    {singleJob?.status}
                  </div>
                </div>
                <p>
                  {singleJob?.jobData?.jobDescription.substring(0, 120)}...
                  <Link
                    to={`/jobdetails/${singleJob?.jobData?._id}`}
                    className="text-[#1d9cb5]"
                  >
                    know more
                  </Link>
                </p>
              </div>
            </div>
          </div>
        ))}
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
          { length: Math.ceil(allJobs.length / MyAllJobsPerPage) },
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
            currentPage === Math.ceil(allJobs.length / MyAllJobsPerPage)
          }
        >
          Next &rarr;
        </button>
      </div>
    </>
  );
};

export default MyRunningJobs;
