import { BiWorld } from "react-icons/bi";
import { FaHandshake } from "react-icons/fa";
import { MdSecurity } from "react-icons/md";

const MainPoints = () => {
    return (
        <div className="py-20">
            <div className="flex lg:flex-row flex-col justify-between gap-4 pb-12">
                <div className="custom-shadow border-4 border-[#287180] rounded-md w-full lg:w-[400px] h-[260px] p-5 flex flex-col justify-center items-center">
                    <MdSecurity className="lg:text-8xl text-7xl text-[#287180]" />
                    <h4 className="text-3xl pb-2 font-semibold">Strong User Privacy</h4>
                    <p>User's privacy is always our first priority</p>
                </div>
                <div className="custom-shadow border-4 border-[#287180] rounded-md w-full lg:w-[400px] h-[260px] p-5 flex flex-col justify-center items-center">
                    <FaHandshake className="lg:text-8xl text-7xl text-[#287180]" />
                    <h4 className="text-3xl pb-2 font-semibold">User Friendly Experience</h4>
                    <p>Our platform is very easy to use</p>
                </div>
                <div className="custom-shadow border-4 border-[#287180] rounded-md w-full lg:w-[400px] h-[260px] p-5 flex flex-col justify-center items-center">
                    <BiWorld className="lg:text-8xl text-7xl text-[#287180]" />
                    <h4 className="text-3xl pb-2 font-semibold">World Wide Service</h4>
                    <p>Hire your staff from any country</p>
                </div>
            </div>
        </div>
    );
};

export default MainPoints;