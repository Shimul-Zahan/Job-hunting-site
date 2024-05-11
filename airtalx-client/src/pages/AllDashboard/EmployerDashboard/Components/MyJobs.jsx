import { useState, useEffect, useContext, useRef } from "react";
import { AuthContext } from "../../../../providers/AuthProviders";
import { SlWallet } from "react-icons/sl";
import { FaRegEdit } from "react-icons/fa";
import { RiDeleteBin2Line } from "react-icons/ri";
import { Link } from "react-router-dom";
import Swal from "sweetalert2";
import ReactHtmlParser from 'react-html-parser';
import { message } from "antd";
import axios from "axios";
import JoditEditor from "jodit-react";

const MyJobs = () => {
  const [allJobs, setAllJobs] = useState([]);
  console.log("🚀 ~ MyJobs ~ allJobs:", allJobs)
  const [content, setContent] = useState('');
  const editor = useRef(null);
  const { user } = useContext(AuthContext);
  const [currentPage, setCurrentPage] = useState(1);
  const [allPostJobsPerPage] = useState(6);
  const fetchMyJobs = () => {
    const url = `http://localhost:5000/myJobPosts?email=${user?.email}`;
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        setAllJobs(data);
        console.log(data);
      })
      .catch((error) => {
        console.log(error);
      });
  }
  useEffect(() => {
    fetchMyJobs();
  }, []);

  const handleUpdateJob = async (e, id) => {
    e.preventDefault();
    const form = e.target;
    const headline = form.headline.value;
    const jobType = form.jobType.value;
    const jobTitle = form.jobTitle.value;
    const startingSalary = form.startingSalary.value;
    const endingSalary = form.endingSalary.value;
    const jobDescription = form.jobDescription.value;

    const updatedJob = { headline, jobType, jobTitle, startingSalary, endingSalary, jobDescription };
    
    await fetch(`http://localhost:5000/myJobPosts/${id}`, {
      method: 'PUT',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify(updatedJob)
    })
      .then(res => res.json())
      .then(data => {
        console.log(data);
        if (data.modifiedCount > 0) {
          alert('user updated successfullyl');
        }
      })
  }

  const handleDeleteJob = async (_id) => {
    const result = await Swal.fire({
      title: "Are you sure?",
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#3085d6",
      cancelButtonColor: "#d33",
      confirmButtonText: "Yes, delete it!"
    });
    if (result.isConfirmed) {
      try {
        const response = await axios.delete(`http://localhost:5000/myJobPosts/${_id}`);
        if (response.status === 200) {
          await Swal.fire({
            title: "Deleted!",
            text: "Job deleted successfully",
            icon: "success"
          });
          fetchMyJobs();
        } else {
          message.error("Failed to delete job");
        }
      }
      catch (error) {
        console.error("Error deleting job:", error);
        message.error("An error occurred while deleting job");
      }
    }
  };

  // Logic for pagination
  const indexOfLastFlat = currentPage * allPostJobsPerPage;
  const indexOfFirstFlat = indexOfLastFlat - allPostJobsPerPage;
  const currentJobs = allJobs.slice(indexOfFirstFlat, indexOfLastFlat);

  // Change page
  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <>
      <div className="grid lg:grid-cols-3 grid-cols-1 m-3">
        {currentJobs.map((singleJob) => (
          <div className="custom-shadow m-3 p-4 rounded-md" key={singleJob._id}>
            <span className="flex pb-4 justify-end">
              <FaRegEdit onClick={() => document.getElementById('my_modal_2').showModal()} className="border cursor-pointer bg-blue-600 text-white p-1 rounded-md text-3xl" />
              <dialog id="my_modal_2" className="modal">
                <form method="dialog" onSubmit={(event) => handleUpdateJob(event, singleJob._id)} className="modal-backdrop">
                  <div className="custom-shadow bg-white text-black h-[80vh] overflow-y-scroll lg:w-3/4 w-11/12 m-auto p-4 rounded-md mb-7">
                    <h3 className="font-semibold text-center text-3xl">Update your job post</h3>
                    <button className="btn btn-sm btn-circle btn-ghost absolute right-2 top-2">✕</button>
                    <div className="py-8">
                      <h4 className="text-2xl font-semibold">Job Title</h4>
                      <div>
                        <input defaultValue={singleJob.jobTitle} name='jobTitle' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder='e.g: "Virtual Assistant", "Graphic Designer", "Bookkeeper"' type="text" />
                      </div>
                    </div>
                    <div className="">
                      <h4 className="text-2xl font-semibold">Job Headline</h4>
                      <p>Write a compelling headline</p>
                    </div>
                    <div>
                      <input defaultValue={singleJob.headline} name='headline' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder="e.g: I'm looking for a professional data researcher" type="text" />
                    </div>
                    <div className="pt-8">
                      <h4 className="text-2xl font-semibold">Job Type</h4>
                      <select defaultValue={singleJob.jobType} name='jobType' className="bg-gray-100 border border-gray-200 p-3 w-[15%] rounded-md mt-4" id="">
                        <option value="">Select</option>
                        <option value="Full Time">Full Time</option>
                        <option value="Part Time">Part Time</option>
                      </select>
                    </div>
                    <div className="pt-8">
                      <h4 className="text-2xl font-semibold">Salary</h4>
                      <p>How much (US Dollar) do you want to pay per hour?</p>
                      <div className="lg:flex gap-3 items-center">
                        <div className="flex items-center">
                          <input defaultValue={singleJob.startingSalary} name='startingSalary' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4" placeholder='Please enter a number between 3 to 99 (starting salary)' type="text" />
                          <p>/hr</p>
                        </div>
                        <p>to</p>
                        <div className="flex items-center">
                          <input defaultValue={singleJob.endingSalary} name='endingSalary' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4" placeholder='Please enter a number between 3 to 99 (ending salary)' type="text" />
                          <p>/hr</p>
                        </div>
                      </div>
                    </div>
                    <div className="pt-8">
                      <h4 className="text-2xl font-semibold">Job Description</h4>
                      <p>Write a detailed job description. Include all the essential information</p>
                      <div className="w-full gap-5 mt-4">
                        {/* <textarea name='jobDescription' className="bg-gray-100 border border-gray-200 p-3 rounded-md w-full" id=""></textarea> */}
                        <div className="custom-class no-tailwind custom-ul custom-ol">
                          <JoditEditor name='jobDescription' ref={editor} value={singleJob.jobDescription} />
                        </div>
                        {/* <input type="text" onChange={(e) => setContent(e.target.value)} />
                        <Markdown>{content}</Markdown> */}
                      </div>
                    </div>
                    <div>
                      <button type="submit" className="bg-[#1d9cb5] text-white text-xl mt-2 rounded px-4 py-2">Update Job</button>
                    </div>
                  </div>
                </form>
              </dialog>
              <RiDeleteBin2Line onClick={() => handleDeleteJob(singleJob._id)} className="border cursor-pointer bg-red-600 text-white p-1 rounded-md text-3xl" />
            </span>
            <div className="flex justify-between pb-4">
              <div>
                <h3 className="text-2xl font-semibold">
                  {singleJob.jobTitle}
                </h3>
                <p className="mb-3 text-base font-semibold">{singleJob.jobPostDate}</p>
                <p>
                  by{" "}
                  <Link to={`/user/${singleJob.email}`}>
                    <span className="text-[#1d9cb5] capitalize font-semibold cursor-pointer">
                      {singleJob.companyName}
                    </span>
                  </Link>
                </p>
              </div>
              <div className="">
                <span className="border border-black rounded-md font-semibold p-3">
                  {singleJob.jobType}
                </span>
              </div>
            </div>
            <div className="flex gap-2 items-center pb-2 text-lg font-semibold">
              <SlWallet />
              <p>${singleJob.startingSalary}/hr</p> -
              <p>${singleJob.endingSalary}/hr</p>
            </div>
            <div>
              <p className="first-letter:capitalize">
                {ReactHtmlParser(singleJob.jobDescription.substring(0, 120))}...
                <Link to={`/jobdetails/${singleJob._id}`} className="text-[#1d9cb5]">
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
          { length: Math.ceil(allJobs.length / allPostJobsPerPage) },
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
          disabled={currentPage === Math.ceil(allJobs.length / allPostJobsPerPage)}
        >
          Next &rarr;
        </button>
      </div>
    </>
  );
};

export default MyJobs;
