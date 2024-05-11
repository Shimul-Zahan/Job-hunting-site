import { useContext, useEffect, useState } from "react";
import { MdOutlineEmail, MdWorkOutline } from "react-icons/md";
import { SlLocationPin } from "react-icons/sl";
import { TbMessage2 } from "react-icons/tb";
import { Link } from "react-router-dom";
import { AuthContext } from "../../../../providers/AuthProviders";
import { IoMdSearch } from "react-icons/io";
import axios from "axios";
import ReactHtmlParser from 'react-html-parser';

const Alljobseekers = () => {
  const [jobseekers, setJobseekers] = useState([]);
  console.log("🚀 ~ Alljobseekers ~ jobseekers:", jobseekers)
  const [currentPage, setCurrentPage] = useState(1);
  const [allJobsPerPage] = useState(6);
  const [searchValue, setSearchValue] = useState("");
  const [typeSelect, seTypeSelect] = useState("");
  const { user } = useContext(AuthContext);

  // Function to fetch filtered job data
  const fetchFilteredJobs = async () => {
    try {
      const response = await axios.get("http://localhost:5000/filterJobseeker", {
        params: {
          searchValue: searchValue,
          typeSelect: typeSelect,
        },
      });
      setJobseekers(response.data);
    } catch (error) {
      console.error("Error fetching filtered job data:", error);
    }
  };

  useEffect(() => {
    const url = "http://localhost:5000/users/jobseeker";
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        setJobseekers(data);
      })
      .catch((error) => {
        console.log(error);
      });
  }, []);

  // Logic for pagination
  const indexOfLastFlat = currentPage * allJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - allJobsPerPage;
  const currentJobs = jobseekers.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  const handleSearchChange = (e) => {
    setSearchValue(e.target.value);
  };
  const handleTypeSelect = (e) => {
    seTypeSelect(e.target.value);
  };

  useEffect(() => {
    // Call the function to fetch filtered job data
    fetchFilteredJobs();
  }, [searchValue, typeSelect]);
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
          <option value="Name">Name</option>
          <option value="Email">Email</option>
        </select>
      </div>
      <div className="grid lg:grid-cols-3 grid-cols-1 m-3">
        {currentJobs.map((singleJobseeker) => (
          <div
            className="custom-shadow p-4 m-3 rounded-md"
            key={singleJobseeker._id}
          >
            <div className="relative">
              <div>
                <div className="flex lg:flex-row flex-col-reverse justify-between lg:gap-28 gap-2">
                  <div>
                    { user ?
                      <h3 className="text-3xl font-semibold text-[#287180] capitalize">
                        {singleJobseeker.name}
                      </h3> :
                      <h3 className="text-3xl font-semibold text-[#287180] capitalize">
                        {singleJobseeker.name.split(' ')[0]}
                      </h3>
                    }
                    <div className="">
                      <div className={`flex gap-2 items-center`}>
                        <MdWorkOutline className="text-3xl border border-black rounded-full p-1" />
                        {singleJobseeker?.jobPosition && <p>{singleJobseeker?.jobPosition}</p>}
                        {!singleJobseeker?.jobPosition && <p>N/A</p>}
                      </div>
                      <div className="flex gap-2 items-center font-semibold">
                        <SlLocationPin className="text-3xl border border-black rounded-full p-1" />
                        {singleJobseeker?.location && (
                          <p>{singleJobseeker?.location}</p>
                        )}
                        {!singleJobseeker?.location && <p>N/A</p>}
                      </div>
                    </div>
                  </div>
                  <label className="avatar w-28 right-0 absolute">
                    <div className="rounded-full border-2 border-black">
                      <div>
                        <img src={singleJobseeker?.photoURL} alt="User Photo" />
                      </div>
                    </div>
                  </label>
                </div>
                <div className={`flex items-center gap-2 mt-5 ${!user && 'hidden'}`}>
                  <button className="border border-black py-1 px-2 rounded-md">
                    Resume
                  </button>
                  {user && (
                    <TbMessage2 className="border border-black text-4xl p-1 rounded-md" />
                  )}
                </div>
                <div className="pt-6">
                  <h4 className="font-semibold pb-2">Expertise field</h4>
                  <div>
                    <span>
                      {singleJobseeker?.expertiseField && (
                        <span className="border border-black capitalize px-2 py-1 mr-3 rounded-full text-base">
                          {singleJobseeker?.expertiseField}
                        </span>
                      )}
                      {!singleJobseeker?.expertiseField && <p>N/A</p>}
                    </span>
                  </div>
                </div>
              </div>
              {/* <label className="avatar w-40 right-0">
                <div className="rounded-full border-2 border-black">
                  <div>
                    <img src={singleJobseeker?.photoURL} alt="User Photo" />
                  </div>
                </div>
              </label> */}
            </div>
            <div className={`pt-3`}>
              <h4 className={`font-semibold ${!user && 'hidden'}`}>About Me</h4>
              <div className="">
                {singleJobseeker?.about && (
                  <div>
                    <p className={`first-letter:capitalize ${!user && 'hidden'}`}>
                      {ReactHtmlParser(singleJobseeker?.about.substring(0, 120))}...
                      <Link
                        to={`/jobseekerProfile/${singleJobseeker?._id}`}
                        className="text-[#1d9cb5] font-semibold"
                      >
                        <button className="">know more</button>
                      </Link>
                    </p>
                    <Link to={`/jobseekerProfile/${singleJobseeker?._id}`} className={`text-[#1d9cb5] font-semibold ${user && 'hidden'}`}>know more</Link>
                  </div>
                )}
                {!singleJobseeker?.about && (
                  <div>
                    <p className={`first-letter:capitalize ${!user && 'hidden'}`}>
                      N/A...
                      <Link
                        to={`/jobseekerProfile/${singleJobseeker?._id}`}
                        className="text-[#1d9cb5] font-semibold"
                      >
                        <button className="">know more</button>
                      </Link>
                    </p>
                    <Link to={`/jobseekerProfile/${singleJobseeker?._id}`} className={`text-[#1d9cb5] font-semibold ${user && 'hidden'}`}>know more</Link>
                  </div>
                )}
                {/* <Link to={`/user/${singleJobseeker?.email}`}>{!singleJobseeker?.about && <p>N/A</p>}</Link> */}
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
          { length: Math.ceil(jobseekers.length / allJobsPerPage) },
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
            currentPage === Math.ceil(jobseekers.length / allJobsPerPage)
          }
        >
          Next &rarr;
        </button>
      </div>
    </>
  );
};

export default Alljobseekers;
