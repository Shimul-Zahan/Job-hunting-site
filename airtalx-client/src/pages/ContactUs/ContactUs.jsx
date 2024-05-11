import Lottie from "lottie-react";
import contactUSModel from "../../../public/contactUS.json";
import { TfiWorld } from "react-icons/tfi";
import { AiOutlineMail } from "react-icons/ai";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";


const ContactUs = () => {
  const [screenWidth, setScreenWidth] = useState(window.innerWidth);

  useEffect(() => {
    const handleResize = () => {
      setScreenWidth(window.innerWidth);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, []);
  return (
    <div className="mt-16 lg:w-3/4 w-11/12 mx-auto">
      <div className="">
        <div className="flex items-center mx-auto flex-col lg:flex-row-reverse border-4 rounded-xl px-10">
          <div>
            <div>
              <Lottie
                animationData={contactUSModel}
                style={{ height: screenWidth >= 1024 ? 400 : 300, width: screenWidth >= 1024 ? 600 : 250 }}

              />
            </div>
          </div>
          <div className="flex flex-col gap-10">
            <h1 className="text-7xl font-bold text-[#194b65]">Contact Us</h1>
            <div className="flex flex-col gap-5 font-semibold text-3xl">
              <h1>Any questions, feedback, or suggestions?</h1>
              <h1>
                Take advantage of our various free customer focused options
              </h1>
            </div>
          </div>
        </div>
      </div>
      <div className="flex lg:flex-row justify-center my-16">
        <div className="flex flex-col lg:flex-row items-center gap-10">
          <div className="card w-full border-2 border-[#194b65] rounded-xl">
            <div className="card-body">
              <h1 className="flex justify-center">
                <TfiWorld size="3em" />
              </h1>
              <h1 className="font-bold text-3xl text-center">
                Visit our <Link className="link link-primary">support page</Link> to
                get the help that you need
              </h1>
            </div>
          </div>
          <div className="card w-full border-2 border-[#194b65] rounded-xl">
            <div className="card-body">
              <h1 className="flex justify-center">
                <AiOutlineMail size="3em" />
              </h1>
              <div className="text-center">
                <h1 className="font-bold text-3xl">Email us at</h1>
                <h1 className="font-bold text-3xl">
                  <Link className="link link-primary">admin@airtalx.com</Link>
                </h1>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContactUs;
