import { useContext, useEffect, useRef, useState } from "react";
import { AuthContext } from "../../../../providers/AuthProviders";
import { message } from "antd";
import JoditEditor from 'jodit-react';

const PostJob = () => {
    const { user } = useContext(AuthContext);
    const [userData, setUserData] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [defaultDate, setDefaultDate] = useState('');
    const [content, setContent] = useState('');

    const editor = useRef(null);

    useEffect(() => {
        const currentDate = new Date();
        const formattedDate = currentDate.toLocaleDateString('en-US', {
            day: '2-digit',
            month: 'short',
            year: 'numeric'
        });
        setDefaultDate(formattedDate);

        const url = `http://localhost:5000/users?email=${user?.email}`;
        fetch(url)
            .then(res => res.json())
            .then(data => {
                setUserData(data);
                setIsLoading(false)
                console.log(data[0].image);
            })
            .catch(error => {
                setIsLoading(false);
                console.log(error);
            });
    }, [user])
    const PostAJob = (e) => {
        e.preventDefault();
        const form = e.target;
        const headline = form.headline.value;
        const jobType = form.jobType.value;
        const email = user?.email;
        const companyName = user?.name;
        const jobTitle = form.jobTitle.value;
        const startingSalary = form.startingSalary.value;
        const endingSalary = form.endingSalary.value;
        const jobPostDate = defaultDate;
        const jobDescription = content;
        const photoURL = user?.photoURL;
        const memberSince = user?.memberSince;
        const company = user?.company;
        const country = user?.country;
        const industry = user?.industry;
        const companySize = user?.jobCompanySize;
        const aboutCompany = user?.aboutCompany;

        const newJobPost = { headline, jobType, email, companyName, jobTitle, startingSalary, endingSalary, jobPostDate, memberSince, jobDescription, photoURL, company, country, industry, companySize, aboutCompany }
        fetch('http://localhost:5000/newJobPost', {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(newJobPost)
        })
            .then(res => res.json())
            .then(data => {
                if (data.insertedId) {
                    message.success("Job Posted Sucessfully!");
                    form.reset();
                }
                else {
                    message.error("Job Cannot Posted!")
                }
            })
            .catch(error => {
                console.error('Error storing user data:', error);
            });
    }
    return (
        <form onSubmit={PostAJob} className="p-6 pb-0">
            <div className="custom-shadow p-4 rounded-md mb-7">
                <div className="py-8">
                    <h4 className="text-2xl font-semibold">Job Title</h4>
                    <div>
                        <input name='jobTitle' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder='e.g: "Virtual Assistant", "Graphic Designer", "Bookkeeper"' type="text" />
                    </div>
                </div>
                <div className="">
                    <h4 className="text-2xl font-semibold">Job Headline</h4>
                    <p>Write a compelling headline</p>
                </div>
                <div>
                    <input name='headline' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4 w-full" placeholder="e.g: I'm looking for a professional data researcher" type="text" />
                </div>
                <div className="pt-8">
                    <h4 className="text-2xl font-semibold">Job Type</h4>
                    <select name='jobType' className="bg-gray-100 border border-gray-200 p-3 w-[15%] rounded-md mt-4" id="">
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
                            <input name='startingSalary' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4" placeholder='Please enter a number between 3 to 99 (starting salary)' type="text" />
                            <p>/hr</p>
                        </div>
                        <p>to</p>
                        <div className="flex items-center">
                            <input name='endingSalary' className="bg-gray-100 border border-gray-200 p-3 rounded-md mt-4" placeholder='Please enter a number between 3 to 99 (ending salary)' type="text" />
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
                            <JoditEditor ref={editor} value={content} onChange={newContent => setContent(newContent)} />
                        </div>
                        {/* <input type="text" onChange={(e) => setContent(e.target.value)} />
                        <Markdown>{content}</Markdown> */}
                    </div>
                </div>
                <div>
                    <button className="bg-[#1d9cb5] text-white text-xl mt-2 rounded px-4 py-2">Create Job</button>
                </div>
            </div>
        </form>
    );
};

export default PostJob;