import { useContext, useEffect, useState } from "react";
import { SlWallet } from "react-icons/sl";
import { Link } from "react-router-dom";
import { IoMdSearch } from "react-icons/io";
import axios from "axios";
import { TbMessage2 } from "react-icons/tb";
import { AuthContext } from "../../../providers/AuthProviders";
import ReactHtmlParser from 'react-html-parser';

const AllJobs = () => {
  const [allJobs, setAllJobs] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [allJobsPerPage] = useState(6);
  const [searchValue, setSearchValue] = useState("");
  const [typeSelect, seTypeSelect] = useState("");
  const { user } = useContext(AuthContext);

  // Function to fetch filtered job data
  const fetchFilteredJobs = async () => {
    try {
      const response = await axios.get("http://localhost:5000/filterJob", {
        params: {
          searchValue: searchValue,
          typeSelect: typeSelect,
        },
      });
      setAllJobs(response.data);
    } catch (error) {
      console.error("Error fetching filtered job data:", error);
    }
  };

  useEffect(() => {
    const url = "http://localhost:5000/newJobPost";
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        setAllJobs(data);
      })
      .catch((error) => {
        console.log(error);
      });
  }, []);

  useEffect(() => {
    // Call the function to fetch filtered job data
    fetchFilteredJobs();
  }, [searchValue, typeSelect]);
  // Logic for pagination
  const indexOfLastFlat = currentPage * allJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - allJobsPerPage;
  const currentJobs = allJobs.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const handleSearchChange = (e) => {
    setSearchValue(e.target.value);
  };
  const handleTypeSelect = (e) => {
    seTypeSelect(e.target.value);
  };
  return (
    <>
      {/* search functionality */}
      <div className="flex items-center gap-2 justify-center mt-5">
        <label className="input input-bordered flex items-center gap-2">
          <input
            type="text"
            className="grow"
            placeholder="Search"
            value={searchValue}
            onChange={handleSearchChange}
          />
          <IoMdSearch size="1.5em" />
        </label>
        <select
          className="select select-bordered w-full max-w-xs font-semibold"
          value={typeSelect}
          onChange={handleTypeSelect}
        >
          <option value="" disabled>
            Select Type
          </option>
          <option value="Job">Job</option>
          <option value="Employer">Employer</option>
          <option value="Full Time">Full Time</option>
          <option value="Part Time">Part Time</option>
        </select>
      </div>
      <div className="grid lg:grid-cols-3 grid-cols-1 m-3">
        {currentJobs.map((singleJob) => (
          <div className="custom-shadow m-3 p-4 rounded-md" key={singleJob._id}>
            <div className="flex justify-end mb-3">
              <div className="badge badge-primary bg-[#1d9cb5] border-none text-white">{singleJob.jobPostDate}</div>
            </div>
            <div className="flex justify-between items-start pb-4">
              <div>
                <h3 className="text-2xl font-semibold capitalize">
                  {singleJob.jobTitle}
                </h3>
                <p>
                  by{" "}
                  <Link to={`/employeProfile/${singleJob.companyName ? singleJob.companyName : 'undefinedName'}/${singleJob._id}`}>
                    <span className="text-[#1d9cb5] capitalize font-semibold cursor-pointer">
                      {singleJob.companyName}
                    </span>
                  </Link>
                </p>
              </div>
              <div>
                <div className="">
                  <div className="flex gap-2">
                    <p className="border border-black rounded-md font-semibold p-2">
                      {singleJob.jobType}
                    </p>
                    {/* <div>
                      {user && (
                        <TbMessage2 className="border cursor-pointer border-black text-5xl p-1 rounded-md" />
                      )}
                    </div> */}
                  </div>
                </div>
              </div>
            </div>
            <div className="flex gap-2 items-center pb-2 text-lg font-semibold">
              <SlWallet />
              <p>${singleJob.startingSalary}/hr</p> -
              <p>${singleJob.endingSalary}/hr</p>
            </div>
            <div>
              <p>
                {ReactHtmlParser(singleJob.jobDescription.substring(0, 120))}...
                <Link
                  to={`/jobdetails/${singleJob.jobTitle ? singleJob.jobTitle : 'undefinedTitle'}/${singleJob._id}`}
                  className="text-[#1d9cb5]"
                >
                  know more
                </Link>
              </p>
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
          { length: Math.ceil(allJobs.length / allJobsPerPage) },
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
          disabled={currentPage === Math.ceil(allJobs.length / allJobsPerPage)}
        >
          Next &rarr;
        </button>
      </div>
    </>
  );
};

export default AllJobs;
